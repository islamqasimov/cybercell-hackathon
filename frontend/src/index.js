import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx'; // ✅ make sure this path matches your file name exactly

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
