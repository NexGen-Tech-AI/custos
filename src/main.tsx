import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = document.getElementById('root');
if (!root) {
  console.error('ROOT ELEMENT NOT FOUND!');
  document.body.innerHTML = '<h1 style="color: red; font-size: 72px;">ROOT NOT FOUND</h1>';
} else {
  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}