# Shared assertions over actual packaged execution receipts; never host modules.
function Assert-RustDefaultKernelMetadata {
    param([Parameter(Mandatory=$true)]$Execution,[Parameter(Mandatory=$true)][string]$Architecture)
    $emptyDigest='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    $decoySource='df7da080c1bc4e84fef932d828ad82944610d8f2703348a2bdc5e797b9549354'
    $profiles=@(
        @{module='ntfs.sys';count=0;digest=$emptyDigest;source=$decoySource},
        @{module='netio.sys';count=54;digest='8236e7cf77394e1463864c97326e26413533aeab64a74dafcde3fc413638a077';source='77b794cf78f2135b192f9b739b697d793669d57329e8c56fbed4bbab9da6176e'},
        @{module='volmgr.sys';count=0;digest=$emptyDigest;source=$decoySource},
        @{module='disk.sys';count=0;digest=$emptyDigest;source=$decoySource},
        @{module='tcpip.sys';count=0;digest=$emptyDigest;source=$decoySource},
        @{module='ndis.sys';count=48;digest='d00bed4efa4febacd0c01c7508677e472b3487554d7da0c1e5472822e4d2aa9a';source='3288deab416722359ce53bd144b549084be7707b4d10f7481eb34198cc863aa8'}
    )
    $first=if($Architecture -eq 'x64'){[decimal]([UInt64]::Parse('fffff80004400000',[Globalization.NumberStyles]::HexNumber))}else{[decimal]0x84400000L}
    for($index=0;$index -lt $profiles.Count;$index++) {
        $profile=$profiles[$index];$expectedBase=$first+$index*16777216
        $path='C:\Windows\system32\drivers\'+$profile.module
        $providers=@($Execution.synthetic_providers|Where-Object {$_.module -ceq $profile.module})
        $mapped=@($Execution.loaded_modules|Where-Object {$_.name -ceq $profile.module})
        if($providers.Count -ne 1 -or $mapped.Count -ne 1){throw 'Default metadata identity is absent, duplicated, or not actually mapped.'}
        $provider=$providers[0];$module=$mapped[0];$metadata=$provider.metadata_only
        if([decimal]$provider.base -ne $expectedBase -or [decimal]$module.base -ne $expectedBase -or $provider.image_size -ne 24576 -or $module.size -ne 24576 -or $provider.exports -ne $profile.count -or $null -ne $provider.reference_catalog){throw 'Default metadata mapping/base/extent/export profile differs from frozen generated inventory.'}
        if($null -eq $metadata -or $metadata.module -cne $profile.module -or $metadata.guest_path -cne $path -or $metadata.permissions -cne 'r--' -or $metadata.ordinal_base -ne 1 -or @($metadata.named_exports).Count -ne $profile.count -or $metadata.catalog_sha256 -cne $profile.digest -or $metadata.legacy_source_sha256 -cne $profile.source -or $metadata.generated_image_sha256 -notmatch '^[0-9a-f]{64}$' -or $metadata.entry_rva -ne 0 -or $metadata.timestamp -ne 0 -or $metadata.checksum -ne 0){throw 'Default metadata path/names/source/hash/READ-NX/zero-header evidence differs from frozen profile.'}
        # loaded_modules is the public name/base/size projection, not a dump
        # of ModuleCatalog provenance. Only a completed native inventory query
        # publishes accepted-byte provenance; read/lookup-only fixtures must
        # not pretend that an inventory query happened.
        $inventory=@($Execution.kernel_modules.last_inventory)
        if($inventory.Count -gt 0) {
            $rows=@($inventory|Where-Object {$_.name -ceq $profile.module})
            if($rows.Count -ne 1 -or [decimal]$rows[0].base -ne $expectedBase -or $rows[0].image_size -ne $module.size -or $rows[0].provenance.origin -cne 'synthetic_provider' -or $rows[0].provenance.guest_path -cne $path -or $rows[0].provenance.accepted_image_sha256 -cne $metadata.generated_image_sha256){throw 'Queried default metadata lost its actual accepted-byte/path provenance.'}
        }
        $digestText=''
        for($i=0;$i -lt $profile.count;$i++) {
            $item=$metadata.named_exports[$i]
            if($item.ordinal -ne $i+1 -or $item.rva -ne 0x1000+$i*16){throw 'Default metadata invented or reordered an export slot.'}
            $digestText+=[string]$item.ordinal+' '+$item.name+"`n"
        }
        $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($digestText))).ToLowerInvariant()
        if($digest -cne $profile.digest){throw 'Default metadata actual emitted export names/order differ from frozen Python source.'}
    }
}
