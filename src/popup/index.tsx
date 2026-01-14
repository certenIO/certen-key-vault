/**
 * Certen Key Vault - Popup Entry Point
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';

// Check for fullpage mode
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('fullpage') === 'true') {
  document.body.classList.add('fullpage');
}

// Get initial mode from URL
const initialMode = urlParams.get('mode') as 'setup' | 'unlock' | 'approve' | null;

// Mount React app
const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(
    <React.StrictMode>
      <App initialMode={initialMode} />
    </React.StrictMode>
  );
}
