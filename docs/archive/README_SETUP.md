# System Monitor Setup Instructions

## Prerequisites

This advanced system monitoring application requires certain system libraries to run. 

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
    libgtk-3-dev \
    libwebkit2gtk-4.1-dev \
    libssl-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install -y \
    gtk3-devel \
    webkit2gtk4.1-devel \
    openssl-devel \
    libappindicator-gtk3-devel \
    librsvg2-devel
```

### macOS
```bash
brew install gtk+3 webkit2gtk
```

## Running the Application

1. Install dependencies:
```bash
pnpm install
```

2. Run in development mode:
```bash
npm run tauri:dev
```

3. Build for production:
```bash
npm run tauri:build
```

## Features Implemented

### ✅ Advanced UI/UX
- **Dark/Light Theme System**: Automatic theme detection with manual override and persistence
- **Customizable Dashboard**: Drag-and-drop widgets with configurable sizes
- **Mobile-Responsive Design**: Fully responsive layout that works on all screen sizes
- **Real-time Updates**: Live system metrics with smooth animations

### ✅ Performance & Reliability
- **Efficient Monitoring**: Low-overhead system monitoring with configurable intervals
- **Metric Aggregation**: Intelligent data collection and processing
- **Memory Management**: Efficient data structures and cleanup

### 🚧 Security (Partial)
- **Secure Communication**: Uses Tauri's secure IPC for frontend-backend communication
- **No External Dependencies**: Runs completely offline for security

## Architecture

The application uses a modern, modular architecture:

- **Frontend**: React + TypeScript with Tailwind CSS
- **Backend**: Rust with Tauri for native performance
- **State Management**: React Context for themes, local storage for persistence
- **Monitoring**: Native system APIs through sysinfo crate

## Customization

### Dashboard Widgets
Click "Customize Dashboard" to:
- Rearrange widgets by dragging
- Show/hide specific monitors
- Resize widgets (Small, Medium, Large, Full Width)

### Themes
The application supports three theme modes:
- Light: Clean, bright interface
- Dark: Easy on the eyes for extended use
- System: Automatically matches your OS theme

### Performance Tuning
Monitoring intervals and data retention can be configured in the application settings (coming soon).

## Future Enhancements

The architecture is designed to support:
- AI-powered anomaly detection
- Predictive analytics
- Multi-system monitoring
- Advanced alerting
- Historical data analysis
- Export capabilities