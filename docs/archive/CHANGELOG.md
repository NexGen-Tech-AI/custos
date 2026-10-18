# Changelog

## [2.0.0] - 2024-12-19

### 🚀 Major Changes

#### **Removed Mock Data System**
- **Deleted** `src/services/mockTauri.ts` - Complete mock Tauri API
- **Removed** all mock data fallbacks from `AppWrapper.tsx`
- **Eliminated** browser compatibility mode - app now requires Tauri runtime
- **Removed** mock data indicators (yellow banners, window titles)
- **Updated** error handling to show clear message when Tauri not available

#### **Enhanced Real-Time Monitoring**
- **Added** comprehensive GPU monitoring with NVIDIA NVML support
- **Implemented** real-time disk I/O rate tracking
- **Added** network bandwidth rate calculation
- **Enhanced** process monitoring with better metrics
- **Improved** memory monitoring with detailed statistics

#### **New GPU Monitor Component**
- **Created** `src/components/monitors/GpuMonitor.tsx`
- **Added** GPU usage, temperature, memory, and power monitoring
- **Implemented** multi-GPU support with bar charts
- **Added** GPU details table with driver information
- **Integrated** GPU monitor into dashboard widget system

### 🔧 Technical Improvements

#### **Backend Enhancements (Rust)**
- **Enhanced** `src-tauri/src/monitoring.rs` with comprehensive metrics collection
- **Added** `get_gpu_metrics()` method with NVIDIA NVML integration
- **Implemented** `get_disk_metrics()` with I/O rate calculation
- **Added** `get_network_metrics()` with bandwidth tracking
- **Improved** rate calculations using previous state tracking
- **Added** better error handling and logging

#### **Frontend Improvements (React/TypeScript)**
- **Updated** `AppWrapper.tsx` to require Tauri environment
- **Enhanced** `DraggableDashboard.tsx` with GPU monitor widget
- **Improved** error states and loading indicators
- **Added** better type safety and error handling
- **Enhanced** real-time data visualization

#### **Configuration Updates**
- **Updated** `src-tauri/Cargo.toml` to enable NVIDIA feature by default
- **Added** `nvml-wrapper` dependency for GPU monitoring
- **Configured** feature flags for optional GPU support

### 📚 Documentation Updates

#### **README.md**
- **Completely rewritten** to reflect real-time monitoring capabilities
- **Added** comprehensive feature documentation
- **Included** troubleshooting guide
- **Added** GPU monitoring configuration instructions
- **Updated** installation and usage instructions

#### **Removed Outdated Documentation**
- **Deleted** `IMPORTANT_README.md` (mock data references)
- **Deleted** `WINDOWS_DEBUGGING.md` (mock data references)
- **Deleted** `WINDOWS_SETUP.md` (mock data references)
- **Updated** all shell scripts to remove mock data references

### 🛠️ Build and Development

#### **Scripts and Tools**
- **Updated** `run-tauri-standalone.sh` for clean Tauri execution
- **Enhanced** `debug-tauri.sh` with comprehensive diagnostics
- **Created** `start-windows.bat` for Windows users
- **Removed** all mock data references from build scripts

#### **Testing**
- **Maintained** existing test structure
- **Updated** test data to reflect real system metrics
- **Preserved** unit and integration tests

### 🎯 Key Features

#### **Real-Time System Monitoring**
- **CPU**: Usage, frequency, per-core stats, load average
- **Memory**: Total/used/available, swap usage, pressure indicators
- **GPU**: Usage, temperature, memory, power, clock speeds (NVIDIA)
- **Disk**: Space usage, I/O rates, file system info
- **Network**: Interface stats, bandwidth usage, packet counts
- **Processes**: Top processes by CPU/memory usage

#### **Interactive Dashboard**
- **Draggable widgets** with persistent layouts
- **Real-time charts** with historical data
- **Customizable dashboard** with show/hide options
- **Responsive design** for different screen sizes
- **Dark/light theme** support

### 🔒 Security and Performance

#### **Security**
- **Removed** browser compatibility (reduces attack surface)
- **Enhanced** error handling for system access
- **Improved** permission management

#### **Performance**
- **Optimized** for 1-second update intervals
- **Enhanced** rate calculations for accurate metrics
- **Improved** memory usage with better state management

### 🐛 Bug Fixes

- **Fixed** deadlock issues in monitoring service
- **Resolved** memory leaks in metrics collection
- **Fixed** timestamp formatting issues
- **Corrected** rate calculation edge cases

### 📋 Migration Notes

#### **For Developers**
- **Breaking Change**: App no longer works in browser environment
- **New Requirement**: Must run through Tauri runtime
- **GPU Monitoring**: Requires NVIDIA GPU and drivers (optional)
- **Dependencies**: Added `nvml-wrapper` for GPU support

#### **For Users**
- **Installation**: No changes to installation process
- **Usage**: Must use `pnpm run tauri dev` (not browser)
- **GPU Support**: Automatic detection of NVIDIA GPUs
- **Performance**: Improved real-time monitoring accuracy

### 🔮 Future Enhancements

- **AMD GPU support** via ROCm
- **Intel GPU monitoring** via Intel oneAPI
- **Advanced analytics** and trend analysis
- **Alert system** for threshold monitoring
- **Data export** and reporting features
- **Plugin architecture** for custom metrics

---

## [1.0.0] - Previous Version

### Features
- Basic system monitoring with mock data support
- Browser compatibility mode
- Simple dashboard interface
- Limited GPU monitoring capabilities

### Limitations
- Mock data fallbacks
- Browser-only operation
- Limited real-time capabilities
- Basic metrics collection 