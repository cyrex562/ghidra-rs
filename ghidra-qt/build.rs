//! Builds the C++ Qt shell: cxx bridge + vendored ADS + moc/rcc, linked
//! against Qt6 Core/Gui/Widgets (dynamic, LGPL). See spec §2.

use std::env;
use std::path::{Path, PathBuf};

const QT_MODULES: [&str; 3] = ["Core", "Gui", "Widgets"];

/// ADS translation units (src/*.cpp at the pinned commit).
const ADS_SOURCES: &[&str] = &[
    "AutoHideDockContainer.cpp", "AutoHideSideBar.cpp", "AutoHideTab.cpp",
    "DockAreaTabBar.cpp", "DockAreaTitleBar.cpp", "DockAreaWidget.cpp",
    "DockComponentsFactory.cpp", "DockContainerWidget.cpp", "DockFocusController.cpp",
    "DockManager.cpp", "DockOverlay.cpp", "DockSplitter.cpp", "DockWidget.cpp",
    "DockWidgetTab.cpp", "DockingStateReader.cpp", "ElidingLabel.cpp",
    "FloatingDockContainer.cpp", "FloatingDragPreview.cpp", "IconProvider.cpp",
    "PushButton.cpp", "ResizeHandle.cpp", "ads_globals.cpp",
];

/// ADS headers declaring Q_OBJECT classes (need moc).
const ADS_MOC_HEADERS: &[&str] = &[
    "AutoHideDockContainer.h", "AutoHideSideBar.h", "AutoHideTab.h", "DockAreaTabBar.h",
    "DockAreaTitleBar.h", "DockAreaTitleBar_p.h", "DockAreaWidget.h", "DockContainerWidget.h",
    "DockFocusController.h", "DockManager.h", "DockOverlay.h", "DockSplitter.h", "DockWidget.h",
    "DockWidgetTab.h", "ElidingLabel.h", "FloatingDockContainer.h", "FloatingDragPreview.h",
    "PushButton.h", "ResizeHandle.h",
];

fn main() {
    let ads = env::var_os("GHIDRA_QT_ADS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("third_party/ads/src"));
    if !ads.join("DockManager.h").exists() {
        panic!(
            "ghidra-qt: ADS sources not found at {}. Run `git submodule update --init ghidra-qt/third_party/ads`.",
            ads.display()
        );
    }
    let linux = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");

    let mut qt = qt_build_utils::QtBuild::new(QT_MODULES.iter().map(|m| m.to_string()).collect())
        .unwrap_or_else(|e| {
            panic!(
                "ghidra-qt: Qt6 development files not found ({e}). Install them with \
                 `sudo apt install qt6-base-dev qt6-base-private-dev` (spec §8)."
            )
        });
    let version = qt.version();
    if version.major != 6 {
        panic!("ghidra-qt: Qt 6 is required, found Qt {version}");
    }

    let mut includes = qt.include_paths();
    // ADS includes <qpa/qplatformnativeinterface.h>, a QtGui private header.
    let headers = qt_headers_dir(&includes);
    for module in ["QtCore", "QtGui"] {
        let versioned = headers.join(module).join(version.to_string());
        let private_root = versioned.join(module);
        if !private_root.join("private").exists() {
            panic!(
                "ghidra-qt: Qt private headers missing at {}. Install `qt6-base-private-dev`.",
                private_root.display()
            );
        }
        includes.push(versioned);
        includes.push(private_root);
    }
    includes.push(ads.clone());
    includes.push(generate_ads_version_header(&ads));

    let moc_args = || qt_build_utils::MocArguments::default().include_paths(includes.clone());
    let mut moc_cpp = Vec::new();
    for header in ADS_MOC_HEADERS {
        moc_cpp.push(qt.moc().compile(ads.join(header), moc_args()).cpp);
    }
    if linux {
        moc_cpp.push(qt.moc().compile(ads.join("linux/FloatingWidgetTitleBar.h"), moc_args()).cpp);
    }
    moc_cpp.push(qt.moc().compile("cpp/main_window.h", moc_args()).cpp);
    // ADS calls Q_INIT_RESOURCE(ads) itself, so the resource must be named `ads`
    // (qt-build-utils defaults to `ads_qrc`; rcc keeps the last --name given).
    let resources = qt.rcc().custom_args(["--name", "ads"]).compile(ads.join("ads.qrc"));

    let mut build = cxx_build::bridge("src/bridge.rs");
    build
        .std("c++17")
        .define("ADS_STATIC", None)
        .includes(&includes)
        .files(ADS_SOURCES.iter().map(|f| ads.join(f)))
        .files(&moc_cpp)
        .files(resources.file.iter())
        .file("cpp/app.cpp")
        .file("cpp/main_window.cpp")
        .file("cpp/views/views.cpp")
        .warnings(false); // third-party ADS; our own files are reviewed instead
    if linux {
        build.file(ads.join("linux/FloatingWidgetTitleBar.cpp"));
        println!("cargo:rustc-link-lib=xcb");
    }
    qt.cargo_link_libraries(&mut build);
    build.compile("ghidra_qt_shell");

    for path in ["src/bridge.rs", "cpp", "build.rs"] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed={}", ads.display());
    println!("cargo:rerun-if-env-changed=GHIDRA_QT_ADS_DIR");
}

/// Renders ADS's CMake-generated `ads_version.h` from its own template
/// (`cmake/modules/ads_version.h.in`), taking the version from ADS's top-level
/// `project(... VERSION x.y.z)`. Returns the directory to add to the include path.
fn generate_ads_version_header(ads_src: &Path) -> PathBuf {
    let root = ads_src.parent().expect("ADS src dir has a parent");
    let template_path = root.join("cmake/modules/ads_version.h.in");
    let template = std::fs::read_to_string(&template_path)
        .unwrap_or_else(|e| panic!("ghidra-qt: cannot read {}: {e}", template_path.display()));
    let cmake = std::fs::read_to_string(root.join("CMakeLists.txt"))
        .expect("ghidra-qt: cannot read ADS CMakeLists.txt");
    let version = cmake
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("VERSION "))
        .map(str::trim)
        .expect("ghidra-qt: no `VERSION x.y.z` line in ADS CMakeLists.txt");
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "ghidra-qt: unexpected ADS version `{version}`"
    );
    let header = template
        .replace("@QtADS_VERSION_MAJOR@", parts[0])
        .replace("@QtADS_VERSION_MINOR@", parts[1])
        .replace("@QtADS_VERSION_PATCH@", parts[2]);
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("ads_generated");
    std::fs::create_dir_all(&out).expect("create ads_generated dir");
    std::fs::write(out.join("ads_version.h"), header).expect("write ads_version.h");
    out
}

/// The directory containing `QtCore/`, `QtGui/`, ... (parent of the QtCore include path).
fn qt_headers_dir(includes: &[PathBuf]) -> PathBuf {
    includes
        .iter()
        .find(|p| p.ends_with("QtCore"))
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .expect("ghidra-qt: could not locate the Qt headers directory (no QtCore include path)")
}
