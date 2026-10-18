# How to Check if You're Seeing Mock or Real Data

## Step 1: Run the Application
```bash
pnpm run tauri dev
```

## Step 2: Identify Which Window to Check
You'll see TWO things:
1. **Browser tab** (Firefox/Chrome) at http://localhost:5173 - ALWAYS mock data
2. **Tauri application window** - Should show real data (if working correctly)

⚠️ **IMPORTANT**: Check the TAURI WINDOW, not the browser!

## Step 3: Visual Indicators

### A. Check the Window Title
Look at the title bar of the window:
- **"System Monitor (Mock Data)"** = Using mock data ❌
- **"System Monitor (Tauri)"** = Should be using real data ✅
- **"System Monitor"** = Default title (check other indicators)

### B. Check for Warning Banner
Look at the top of the application:
- **Yellow warning banner** saying "⚠️ MOCK DATA MODE" = Mock data ❌
- **No warning banner** = Should be real data ✅

### C. Check the Data Itself
Look at the system information displayed:

**Mock Data looks like:**
- Hostname: `DESKTOP-MOCK123`
- OS: `MockOS 10.0`
- CPU: `Mock Intel Core i9-9900K @ 3.60GHz`
- Memory: `32.0 GB`
- CPU Cores: `8`

**Real Data should show YOUR actual system:**
- Hostname: Your actual hostname
- OS: `Linux` with your Ubuntu version
- CPU: Your actual processor
- Memory: Your actual RAM amount

## Step 4: Open Developer Console

In the **Tauri window** (not browser):
1. Press **F12** or right-click → "Inspect Element"
2. Go to the **Console** tab
3. Look for these messages:

### Good (Real Data):
```
=== Tauri v2 Detection Service ===
✓ window.__TAURI__ found
✓ Tauri v2 core.invoke found
TAURI DETECTED - NOT USING MOCK SERVICE
Using Tauri v2 core.invoke
=== get_system_info called ===
System info retrieved successfully:
  Hostname: [your-actual-hostname]
  OS: Linux [version]
  CPU: [your-actual-cpu]
```

### Bad (Mock Data):
```
=== Tauri v2 Detection Service ===
✗ No Tauri environment detected
USING MOCK SERVICE - NOT REAL SYSTEM DATA
```

## Step 5: Terminal Output Check

Look at your terminal where you ran `pnpm run tauri dev`:

### Good Signs:
```
=== Tauri App Setup ===
App is initializing...
Opening devtools for main window
Tauri setup complete
=== get_system_info called ===
System info retrieved successfully:
  Hostname: [actual]
  OS: Linux [version]
  CPU: [actual CPU]
```

### Bad Signs:
```
symbol lookup error: ... libpthread.so.0 ...
WebProcess didn't exit as expected
```

## Quick Test Commands

### Test 1: Check if window.__TAURI__ exists
In the Tauri window's console, type:
```javascript
window.__TAURI__
```
- If it returns `undefined` → Tauri not detected ❌
- If it returns an object → Check its structure ✅

### Test 2: Check the API structure
```javascript
// For Tauri v2:
window.__TAURI__.core
window.__TAURI__.event
```

### Test 3: Try calling a command directly
```javascript
// For Tauri v2:
await window.__TAURI__.core.invoke('get_system_info')
```
- If it returns real system info → Working ✅
- If it throws an error → Not working ❌

## Summary Checklist

- [ ] I'm looking at the Tauri window, NOT the browser
- [ ] Window title shows "(Tauri)" not "(Mock Data)"
- [ ] No yellow warning banner visible
- [ ] System info shows my actual hardware, not "Mock" values
- [ ] Console shows "TAURI DETECTED" message
- [ ] window.__TAURI__ exists in console
- [ ] No snap-related errors in terminal