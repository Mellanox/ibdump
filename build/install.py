#!/usr/bin/python

import platform
import os
import sys
import glob
import shutil
import zipfile

isWin = 'Linux' not in platform.system()
currDir = os.path.dirname(os.path.realpath(__file__))
osPrefix = ("/tmp", "C:\\tmp")[isWin]
TMP_PATH = os.path.join(osPrefix, "ibdump.logs."  + str(os.getpid()))
winBinDestDir = "C:\\Program Files\\Mellanox"

def prepareBuildEnv():
    cleanUp()
    print "-I- Create tmp path: " + TMP_PATH
    os.makedirs(TMP_PATH)

def cleanUp(withExit=0, rc=0):
    print "-I- Clean up was called ..."
    if os.path.exists(TMP_PATH):
        try:
            shutil.rmtree(TMP_PATH)
        except Exception, e:
            print "-E- Failed to clean up, %s" % str(e)
            sys.exit(1)
    if withExit:
        if rc:
            sys.exit(1)
        else:
            sys.exit(0)
        

def installWinIbdump():
    ibdumpZipFilePtrn = os.path.join(currDir, "windows", "*.zip")
    filesList = glob.glob(ibdumpZipFilePtrn)
    if not filesList:
        print "-E- No zip file was found for windows !"
        cleanUp(withExit=1, rc=1)
    print "-I- Extracting Zip file for windows: %s" % filesList[0]
    ibdumpZipFile = zipfile.ZipFile(filesList[0], "r")
    ibdumpZipFile.extractall(TMP_PATH)
    winVer = int(platform.version().split(".")[-1])
    if winVer < 9200 and winVer > 7200:
        winVer = "Win7"
    elif winVer < 9600 and winVer >= 9200:
        winVer = "Win8"
    else:
        print "-E- This OS is not supported"
        cleanUp(withExit=1, rc=32)
    print "-I- Copying ibdump for %s" % winVer
    destPath = os.path.join(TMP_PATH, winVer, "ibdump.exe")
    shutil.copy(destPath, winBinDestDir)
    print "-I- Ibdump installed successfully in: \"%s\"" % winBinDestDir

def installLinuxIbdump():
    ibdumpPkgPtrn = os.path.join(currDir, "linux", "*.tgz")
    filesList = glob.glob(ibdumpPkgPtrn)
    if not filesList:
        print "-E- No ibdump package was found !"
        cleanUp(withExit=1, rc=1)
    ibdumpPkg = filesList[0]
    print "-I- Untar ibdump package: %s" % ibdumpPkg
    cmd = "tar -xzf %s -C %s" % (ibdumpPkg, TMP_PATH)
    os.system(cmd)
    ibdumpVer = ((ibdumpPkg.split("/")[-1]).split(".tgz")[0]).split("_")[0][:-2]
    if ibdumpVer == "":
        print "-E- Failed to get ibdump version from : " + ibdumpPkg
        cleanUp(withExit=1, rc=1)
    os.chdir(TMP_PATH)
    os.chdir(ibdumpVer)
    print "-I- Compiling and building ibdump ..."
    rc = os.system("make && make install")
    if rc:
        print "-E- Build failed"
        cleanUp(withExit=1, rc=rc)
    print "-I- Ibdump was installed successfully"

def main():
    prepareBuildEnv()
    if isWin:
        print "-I- Install ibdump for Windows ..."
        installWinIbdump()
    else:
        print "-I- Building and installing ibdump ... "
        installLinuxIbdump()
    cleanUp()

if __name__ == "__main__":
    try:
        main()
    except Exception, e:
        print "-E- Installation failed, %s" % str(e)
        cleanUp(withExit=1, rc=5)

