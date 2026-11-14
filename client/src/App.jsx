import React from 'react';
import { ErrorBoundary } from '@krusch/toolkit/react';
import { BreakerCockpit } from './components/BreakerCockpit.jsx';
import './styles.css';

export default function App() {
    return (
        <ErrorBoundary>
            <BreakerCockpit />
        </ErrorBoundary>
    );
}
