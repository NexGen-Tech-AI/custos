import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

console.log('=== MAIN.TSX LOADED ===');

const root = document.getElementById('root');
if (!root) {
  console.error('ROOT ELEMENT NOT FOUND!');
  document.body.innerHTML = '<h1 style="color: red; font-size: 72px;">ROOT NOT FOUND</h1>';
} else {
  console.log('ROOT FOUND, RENDERING...');

  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );

  console.log('RENDER COMPLETE');
}