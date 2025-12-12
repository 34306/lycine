#!/bin/bash
# version 1.1
UTIL=$1
TARGET_PATH=${CODESIGNING_FOLDER_PATH}
TARGET_SRC_PATH=${PROJECT_DIR}/${TARGET_NAME}

if [ -z ${WRAPPER_EXTENSION} ]; then
    BIN_PATH=${TARGET_PATH}
else
    BIN_PATH=${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}
fi

if [ ! -d ${TARGET_SRC_PATH} ]; then
    TARGET_SRC_PATH=${PROJECT_DIR}
fi

echo "TARGET_PATH: ${TARGET_PATH}"
echo "BIN_PATH: ${BIN_PATH}"

function getType {
    JBDEV_CONF_PATH=${PROJECT_DIR}/jbdev.plist
    JBDEV_TYPE="app"
    if [ ! -f ${JBDEV_CONF_PATH} ]; then
        echo "Could not find ${JBDEV_CONF_PATH}, exit"
        return -1
    fi
    _T=$(/usr/libexec/PlistBuddy ${JBDEV_CONF_PATH} -c "Print :type")
    if [ x$_T = "xjailbreak" ]; then
        JBDEV_TYPE="jailbreak"
    elif [ x$_T = "xtrollstore" ]; then
        JBDEV_TYPE="trollstore"
    fi
    if [ ${JBDEV_TYPE} = "app" ]; then
        echo "Skip build for app"
    fi
}

function checkEnv {
    if [ ${JBDEV_TYPE} = "jailbreak" ]; then
        if [ -z ${THEOS} ]; then
            echo "THEOS not set"
            return -1
        fi
    fi
}

function logosCompile {
    for i in `find ${TARGET_SRC_PATH} \( -name "*.x" -o -name "*.xm" \)  -exec ls {} \;`; do
        if [ "${i: -2}" = ".x" ]; then
            echo "compile $i -> $i.m"
            ${THEOS}/bin/logos.pl -c warnings=error $i > $i.m
        elif [ "${i: -3}" = ".xm" ]; then
            echo "compile $i -> $i.mm"
            ${THEOS}/bin/logos.pl -c warnings=error $i > $i.mm
        fi
        if [ $? -ne 0 ]; then
            echo "compile failed $i"
            return -1
        fi
    done
}

function buildHooks {
    echo "Building launchdhook.dylib..."
    pushd ${PROJECT_DIR}/launchdhook > /dev/null
    make clean 2>/dev/null || true
    make
    if [ $? -ne 0 ]; then
        echo "Failed to build launchdhook.dylib"
        popd > /dev/null
        return -1
    fi
    ldid -S launchdhook.dylib 2>/dev/null || true
    popd > /dev/null
    
    echo "Building xpcproxyhook.dylib..."
    pushd ${PROJECT_DIR}/xpcproxyhook > /dev/null
    make clean 2>/dev/null || true
    make
    if [ $? -ne 0 ]; then
        echo "Failed to build xpcproxyhook.dylib"
        popd > /dev/null
        return -1
    fi
    ldid -S xpcproxyhook.dylib 2>/dev/null || true
    popd > /dev/null
    
    echo "Hooks built successfully!"
}

function copyResources {
    echo "Copying resources to app bundle..."
    
    # Copy ldid
    if [ -f ${PROJECT_DIR}/Resources/ldid ]; then
        cp ${PROJECT_DIR}/Resources/ldid ${TARGET_PATH}/ldid
        chmod +x ${TARGET_PATH}/ldid
    fi
    
    # Copy insert_dylib
    if [ -f ${PROJECT_DIR}/Resources/insert_dylib ]; then
        cp ${PROJECT_DIR}/Resources/insert_dylib ${TARGET_PATH}/insert_dylib
        chmod +x ${TARGET_PATH}/insert_dylib
    fi
    
    # Copy launchd_ent.plist
    if [ -f ${PROJECT_DIR}/Resources/launchd_ent.plist ]; then
        cp ${PROJECT_DIR}/Resources/launchd_ent.plist ${TARGET_PATH}/launchd_ent.plist
    fi
    
    # Copy bootstrap
    if [ -f ${PROJECT_DIR}/Resources/bootstrap.tar.zst ]; then
        cp ${PROJECT_DIR}/Resources/bootstrap.tar.zst ${TARGET_PATH}/bootstrap.tar.zst
    fi
    
    # Copy hooks
    if [ -f ${PROJECT_DIR}/launchdhook/launchdhook.dylib ]; then
        cp ${PROJECT_DIR}/launchdhook/launchdhook.dylib ${TARGET_PATH}/launchdhook.dylib
    fi
    
    if [ -f ${PROJECT_DIR}/xpcproxyhook/xpcproxyhook.dylib ]; then
        cp ${PROJECT_DIR}/xpcproxyhook/xpcproxyhook.dylib ${TARGET_PATH}/xpcproxyhook.dylib
    fi
    
    echo "Resources copied successfully!"
}

function doSign {
    ENT_PATH=${TARGET_SRC_PATH}/${TARGET_NAME}.ent
    if [ ! -z ${CODE_SIGN_ENTITLEMENTS} ]; then
        ENT_PATH=${CODE_SIGN_ENTITLEMENTS}
    fi
    codesign --remove-signature ${TARGET_PATH}
    if [ -f ${TARGET_PATH}/_CodeSignature ]; then
        rm -rf ${TARGET_PATH}/_CodeSignature
    fi
    if [ -f ${TARGET_PATH}/embedded.mobileprovision ]; then
        rm -rf ${TARGET_PATH}/embedded.mobileprovision
    fi
    if [ -f ${ENT_PATH} ]; then
        echo "Find ${ENT_PATH}, Signing ..."
        if [ -f ${BIN_PATH} ]; then
            ldid -S${ENT_PATH} ${BIN_PATH}
        else
            echo "Could not find binary ${BIN_PATH}, exit"
            return -1
        fi
    else
        echo "Could not find entitlement ${ENT_PATH}"
        echo "ldid -S ${BIN_PATH}"
        ldid -S ${BIN_PATH}
    fi
}

function copyToLayout {
    LAYOUT_TEMPLATE=layout_root
    if [ x${THEOS_PACKAGE_SCHEME} = "xrootless" ]; then
        LAYOUT_TEMPLATE=layout_rootless
    elif [ x${THEOS_PACKAGE_SCHEME} = "xroothide" ]; then
        LAYOUT_TEMPLATE=layout_roothide
    fi
    if [ -d ${LAYOUT_TEMPLATE} ]; then
        echo "Find ${LAYOUT_TEMPLATE}"
        rsync -az ${LAYOUT_TEMPLATE}/* layout/
    fi
    if [ ! -f layout/DEBIAN/control ]; then
        echo "Could not find layout/DEBIAN/control, exit"
        return -1
    fi
    LAYOUT_TARGET_DIR=layout${INSTALL_PATH}
    if [ ! -d ${LAYOUT_TARGET_DIR} ]; then
        mkdir -p ${LAYOUT_TARGET_DIR}
    fi
    LAYOUT_TARGET_PATH=${LAYOUT_TARGET_DIR}/${FULL_PRODUCT_NAME}
    if [ -f ${LAYOUT_TARGET_PATH} ]; then
        echo "Find old file, delete ${LAYOUT_TARGET_PATH}"
        rm -rf ${LAYOUT_TARGET_PATH}
    fi
    rsync -az --exclude="payload.*" ${TARGET_PATH} ${LAYOUT_TARGET_DIR}/
}

function doPackage() {
    if [ ${JBDEV_TYPE} = "jailbreak" ]; then
        if [ ! -f jbdev.Makefile ]; then
            echo "include ${THEOS}/makefiles/common.mk" > jbdev.Makefile
        fi
        if [ ! -d packages ]; then
            mkdir packages
        fi
        make clean
        if [ x${THEOS_PACKAGE_SCHEME} = "x" ]; then
            echo "make -f jbdev.Makefile package"
            make -f jbdev.Makefile package
        else
            echo "make -f jbdev.Makefile package THEOS_PACKAGE_SCHEME=${THEOS_PACKAGE_SCHEME}"
            make -f jbdev.Makefile package THEOS_PACKAGE_SCHEME=${THEOS_PACKAGE_SCHEME}
        fi
        if [ $? -ne 0 ]; then
            return -1
        fi
        DEB_PATH=$(cat .theos/last_package)
        echo "cp -f ${DEB_PATH} ${TARGET_PATH}/payload.deb"
        cp -f ${DEB_PATH} ${TARGET_PATH}/payload.deb
    elif [ ${JBDEV_TYPE} = "trollstore" ]; then
        TARGET_DIR=${TARGET_PATH}/..
        if [ -d ${TARGET_DIR}/Payload ]; then
            rm -rf {TARGET_DIR}/Payload
        fi
        mkdir -p ${TARGET_DIR}/Payload
        cp -rfp ${TARGET_PATH} ${TARGET_DIR}/Payload/
        pushd ${TARGET_DIR}
        zip -qr ${TARGET_NAME}.tipa Payload
        popd
        rm -rf ${TARGET_DIR}/Payload
        TIPA_PATH=${TARGET_DIR}/${TARGET_NAME}.tipa
        echo "cp -f ${TIPA_PATH} ${TARGET_PATH}/payload.tipa"
        cp -f ${TIPA_PATH} ${TARGET_PATH}/payload.tipa
    fi
    cp -f jbdev.plist ${TARGET_PATH}/ # 强制拷贝防止sparse.ipa不带文件
}

echo "........ Start building ........"
getType || exit -1
checkEnv || exit -1
if [ x$UTIL = "xlogos" ]; then
    logosCompile || exit -1
    exit 0
fi

# Build hooks first
buildHooks || exit -1

doSign || exit -1

# Copy resources after signing
copyResources || exit -1

if [ ${JBDEV_TYPE} = "jailbreak" ] && [ x${JBDEV_NO_COPY} != "xYES" ] ; then
    copyToLayout || exit -1
fi
if [ x${JBDEV_PACKAGE} = "xYES" ]; then
    doPackage || exit -1
fi
echo "........ Done building ........"

