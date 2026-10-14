using System;
using System.IO;

namespace DeployerStage;

public static class Stage
{
    public static void Run()
    {
        // This second stage creates only a fixed guest canary.
        File.WriteAllText(@"C:\Users\Alex\Downloads\emumee-stage-two.txt",
                          "benign embedded stage reached");
    }
}
