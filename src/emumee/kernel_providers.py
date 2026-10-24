"""Synthetic, read-only provider catalogs; no trust or crypto implementation.

Named export metadata was inspected statically from the local Windows provider
files during development. No Microsoft code bytes are included or discovered
at runtime. The CI unnamed ordinals 1..3 are deliberately not represented.
"""

import ntpath

from speakeasy.windows.common import JitPeFile
from speakeasy.windows.loaders import PeLoader


PROVIDER_EXPORTS = {
    'ci': (4, (
        'CiCheckSignedFile', 'CiFindPageHashesInCatalog', 'CiFindPageHashesInSignedFile',
        'CiFreePolicyInfo', 'CiGetCertPublisherName', 'CiGetPEInformation',
        'CiInitialize', 'CiSetTrustedOriginClaimId', 'CiValidateFileObject',
        'CiVerifyHashInCatalog',
    )),
    'cng': (1, (
        'BCryptAddContextFunctionProvider', 'BCryptCloseAlgorithmProvider', 'BCryptCreateHash',
        'BCryptCreateMultiHash', 'BCryptDecapsulate', 'BCryptDecrypt', 'BCryptDeriveKey',
        'BCryptDeriveKeyCapi', 'BCryptDeriveKeyPBKDF2', 'BCryptDestroyHash', 'BCryptDestroyKey',
        'BCryptDestroySecret', 'BCryptDuplicateHash', 'BCryptDuplicateKey', 'BCryptEncapsulate',
        'BCryptEncrypt', 'BCryptEnumAlgorithms', 'BCryptEnumProviders', 'BCryptExportKey',
        'BCryptFinalizeKeyPair', 'BCryptFinishHash', 'BCryptFreeBuffer', 'BCryptGenRandom',
        'BCryptGenerateKeyPair', 'BCryptGenerateSymmetricKey', 'BCryptGetFipsAlgorithmMode',
        'BCryptGetProperty', 'BCryptHash', 'BCryptHashData', 'BCryptImportKey', 'BCryptImportKeyPair',
        'BCryptKeyDerivation', 'BCryptOpenAlgorithmProvider', 'BCryptProcessMultiOperations',
        'BCryptRegisterConfigChangeNotify', 'BCryptRegisterProvider', 'BCryptResolveProviders',
        'BCryptSecretAgreement', 'BCryptSetProperty', 'BCryptSignHash',
        'BCryptUnregisterConfigChangeNotify', 'BCryptUnregisterProvider', 'BCryptVerifySignature',
        'CngGetFipsAlgorithmMode', 'EntropyPoolTriggerReseedForIum', 'EntropyProvideData',
        'EntropyRegisterCallback', 'EntropyRegisterSource', 'EntropyUnregisterSource',
        'SslDecrementProviderReferenceCount', 'SslDecryptPacket', 'SslEncryptPacket',
        'SslExpandNextGenTrafficKey', 'SslExpandWriteKey', 'SslExportKey', 'SslExportKeyingMaterial',
        'SslFreeObject', 'SslImportKey', 'SslIncrementProviderReferenceCount', 'SslLookupCipherLengths',
        'SslLookupCipherSuiteInfo', 'SslOpenProvider', 'SymCrypt802_11SaeCustomCommitCreate',
        'SymCrypt802_11SaeCustomCommitProcess', 'SymCrypt802_11SaeCustomCreatePT',
        'SymCrypt802_11SaeCustomDestroy', 'SymCrypt802_11SaeCustomInit',
        'SymCrypt802_11SaeCustomInitH2E', 'SystemPrng',
    )),
}


def configure(cfg):
    modules = cfg['modules']['system_modules']
    for index, (name, path) in enumerate((('ci', r'C:\Windows\system32\ci.dll'),
                                        ('cng', r'C:\Windows\system32\drivers\cng.sys'))):
        if not any(module['name'] == name for module in modules):
            modules.append({'name': name, 'base_addr': hex(0xE0000000 + index * 0x1000000),
                'path': path, 'driver': None})


def metadata_image(name, arch, base, path):
    ordinal_base, exports = PROVIDER_EXPORTS[name]
    jit = JitPeFile(arch, base=base, mod_name=ntpath.basename(path), exports=exports)
    pe = jit.basepe
    pe.parse_data_directories(directories=[0])
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0
    pe.FILE_HEADER.TimeDateStamp = 0
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.DIRECTORY_ENTRY_EXPORT.struct.Base = ordinal_base
    for section in pe.sections:
        section.Characteristics = 0x40000040  # Initialized readable data; no write/execute.
    data = bytearray(pe.write())
    for section in pe.sections:
        if section.Name.rstrip(b'\0') == b'.text':
            start, size = section.PointerToRawData, section.SizeOfRawData
            data[start:start + size] = b'\xcc' * size  # Inert placeholders, never function bodies.
    loader = PeLoader(data=bytes(data), base_override=base, emu_path=path)
    image = loader.make_image()
    image.name = name
    image.module_type = 'dll'
    image.default_export_mode = 'native'
    image.entry_points = []
    for exported in image.exports:
        exported.execution_mode = 'native'
    return image


def report(kernel):
    output = []
    for module in kernel.modules:
        if module.name not in PROVIDER_EXPORTS:
            continue
        output.append({'name': ntpath.basename(module.emu_path), 'path': module.emu_path,
            'base': hex(module.base), 'size': module.image_size,
            'named_exports': [{'name': item.name, 'address': hex(item.address), 'ordinal': item.ordinal}
                              for item in module._image.exports],
            'permissions': 'r--', 'executable': False,
            'scope': 'Synthetic named-export metadata catalog only; no function code, trust verdicts, cryptographic results or boot initialization; calls and writes stop at native protection boundaries',
            'unnamed_ordinals_modeled': False})
    return output
