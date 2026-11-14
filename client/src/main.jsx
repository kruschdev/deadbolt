import React from 'react';
import { createRoot } from 'react-dom/client';
import { setReactRuntime } from '@krusch/toolkit/react';
import App from './App.jsx';

setReactRuntime(React);
createRoot(document.getElementById('root')).render(<App />);
