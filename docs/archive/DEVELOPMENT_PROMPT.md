# SYSTEM DETECTION DEVELOPMENT PROMPT

## CRITICAL REQUIREMENTS

### 0. EXPERT-LEVEL DEVELOPMENT STANDARDS
- **Rust**: Expert-level Rust programming with proper error handling, async/await patterns, and performance optimization
- **React**: Expert-level React with TypeScript, proper hooks usage, and optimized rendering
- **TypeScript**: Strict TypeScript with proper type definitions and interfaces
- **TailwindCSS**: Expert-level styling with responsive design and modern UI patterns
- **Code Quality**: Production-ready, maintainable, and scalable code
- **Performance**: Optimized for speed and efficiency at every level
- **Architecture**: Clean, modular, and well-structured codebase

**NEVER REDUCE THE APPLICATION TO AVERAGE QUALITY** - Maintain the high standards of the existing codebase.

### 1. TAURI VERSION POLICY - NEVER REVERT TO V1
- **TAURI VERSION 1 IS DEAD** - Never consider it as an option
- Always use Tauri v2 for all development
- If you see any Tauri v1 references, immediately correct them to v2
- The `tauri.conf.json` is configured for v2 - never change this
- In `Cargo.toml`, always use:
  ```toml
  tauri = { version = "2", features = ["app-all"] }
  tauri-build = { version = "2" }
  ```

### 2. MINIMAL OVERHEAD REQUIREMENTS
- **CPU Usage**: Must be under 5% during normal operation
- **Memory Usage**: Must be under 100MB total application memory
- **Polling Frequency**: 1-second intervals for real-time monitoring
- **Response Time**: When polled, data must be collected and returned within 100ms
- **Smart Detection**: Hardware detection should happen ONCE at startup, then cache results

### 3. PERFORMANCE OPTIMIZATION RULES

#### Frontend (React/TypeScript)
- Use `useMemo` and `useCallback` for expensive calculations
- Only re-render components when data actually changes
- Canvas redrawing should only occur when metrics change, not on every render
- Disable exotic hardware monitors by default (set `visible: false`)
- Only show hardware monitors when hardware is actually detected

#### Backend (Rust)
- Use `once_cell::sync::Lazy` for one-time hardware detection
- Cache hardware detection results in static variables
- Limit process collection to top 20 processes by CPU usage
- Skip expensive I/O and network monitoring for processes
- Use selective `sysinfo` refreshes (only CPU, memory, processes if empty)
- Disable exotic hardware detection vectors (DPUs, NPUs, FPGAs, ASICs, Quantum Processors)

#### Polling Strategy
- Primary polling interval: 1 second
- Fallback polling interval: 1 second
- High-performance monitoring interval: 1 second
- Kernel monitoring interval: 1 second

### 4. DEPENDENCY MANAGEMENT

#### Required Dependencies (Cargo.toml)
```toml
[dependencies]
tauri = { version = "2", features = ["app-all"] }
tauri-build = { version = "2" }
sysinfo = "0.30"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
dashmap = "5.5"
crossbeam = "0.8"
once_cell = "1.19"
rayon = "1.8"
bincode = "1.3"
hostname = "0.3"
os_info = "3.7"
nvml-wrapper = { version = "0.11", optional = true }

[features]
nvidia = ["dep:nvml-wrapper"]
```

#### Never Include
- `shell-open` feature (doesn't exist in Tauri v2)
- Tauri v1 dependencies
- Unused dependencies

### 5. SYSTEM INFORMATION ACCURACY

#### CPU Metrics
- Use `sysinfo::System::physical_core_count()` for physical cores
- Use `system.cpus().len()` for logical threads
- CPU frequency from `sysinfo` is already in MHz (no division needed)
- Ensure proper thread counts using `process.thread_kind()`

#### Memory Metrics
- Set `cached_bytes` and `buffer_bytes` to 0 on Windows (sysinfo doesn't expose these)
- Use `sys.refresh_memory()` for accurate memory data

#### Process Metrics
- Limit to top 20 processes by CPU usage
- Skip expensive I/O/network monitoring (set to 0)
- Use `process.thread_kind()` for thread counts
- Set priority to 0 (sysinfo doesn't expose process priority)

### 6. ERROR PREVENTION CHECKLIST

Before making any changes:
1. ✅ Verify Tauri version is v2 in all files
2. ✅ Check that all dependencies are properly declared
3. ✅ Ensure sysinfo API calls are platform-appropriate
4. ✅ Verify polling intervals are not faster than 5 seconds
5. ✅ Confirm hardware detection is cached/one-time only
6. ✅ Check that exotic hardware monitors are disabled by default
7. ✅ Verify CPU/memory/process metrics are accurate
8. ✅ Test compilation before committing changes

### 7. COMMON MISTAKES TO AVOID

#### Tauri Version Issues
- ❌ Never revert to Tauri v1
- ❌ Never use `shell-open` feature
- ❌ Never mix v1 and v2 dependencies

#### Performance Issues
- ❌ Don't poll faster than 5 seconds
- ❌ Don't refresh all sysinfo data on every call
- ❌ Don't collect thousands of processes
- ❌ Don't redraw UI on every render
- ❌ Don't detect exotic hardware repeatedly

#### API Usage Issues
- ❌ Don't divide CPU frequency by 1,000,000 (sysinfo provides MHz)
- ❌ Don't call non-existent methods like `process.priority()`
- ❌ Don't use `sysinfo::System::cached_memory()` on Windows
- ❌ Don't hardcode thread counts to 1

### 8. TESTING REQUIREMENTS

Before considering any change complete:
1. ✅ Rust backend compiles without warnings
2. ✅ Frontend builds successfully
3. ✅ Application launches without port conflicts
4. ✅ CPU and memory usage are within limits
5. ✅ System information is accurate
6. ✅ No exotic hardware monitors appear unless hardware is detected

### 9. RECOVERY PROCEDURE

If the application breaks:
1. Immediately revert to the last working commit
2. Identify the specific issue (Tauri version, dependency, API usage)
3. Apply the minimal fix needed
4. Test thoroughly before proceeding
5. Document the issue and solution

### 10. FUTURE DEVELOPMENT FOCUS

After the monitoring app is stable:
- Focus on "the money makers" - security and optimization apps
- Maintain the same performance standards
- Apply lessons learned from monitoring app development

---

**REMEMBER**: This is a monitoring application that should be lightweight and efficient. Every decision should prioritize minimal resource usage while maintaining accuracy and responsiveness. 