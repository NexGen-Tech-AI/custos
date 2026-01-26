export default function SimpleTest() {
  return (
    <div style={{
      width: '100vw',
      height: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      color: 'white',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      padding: '20px',
      boxSizing: 'border-box'
    }}>
      <h1 style={{ fontSize: '48px', marginBottom: '20px', textShadow: '2px 2px 4px rgba(0,0,0,0.3)' }}>
        ✅ React is Rendering!
      </h1>
      <p style={{ fontSize: '24px', marginBottom: '10px' }}>
        System Monitor Test
      </p>
      <p style={{ fontSize: '16px', opacity: 0.9 }}>
        If you see this, React and Tauri are working correctly
      </p>
      <div style={{
        marginTop: '40px',
        padding: '20px',
        backgroundColor: 'rgba(255,255,255,0.2)',
        borderRadius: '10px',
        backdropFilter: 'blur(10px)'
      }}>
        <p style={{ margin: 0 }}>Check the DevTools console (F12) for more information</p>
      </div>
    </div>
  );
}
