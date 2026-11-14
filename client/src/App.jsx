import React from 'react';
import { ErrorBoundary } from '@krusch/toolkit/react';
import { BreakerCockpit } from './components/BreakerCockpit.jsx';
import './styles.css';

export default function App() {
    return (
        <ErrorBoundary
            fallbackRender={({ error, reset }) => (
                <div
                    role="alert"
                    style={{
                        minHeight: '100vh',
                        background: '#07090E',
                        color: '#F8FAFC',
                        fontFamily: 'system-ui, -apple-system, sans-serif',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: '2rem'
                    }}
                >
                    <div
                        style={{
                            maxWidth: '560px',
                            width: '100%',
                            background: '#0F1420',
                            border: '1px solid rgba(239, 68, 68, 0.45)',
                            borderRadius: '12px',
                            padding: '1.5rem'
                        }}
                    >
                        <h2 style={{ margin: '0 0 0.5rem', color: '#FCA5A5', fontSize: '1.1rem' }}>
                            DEADBOLT Breaker Panel Recovery Gate
                        </h2>
                        <p style={{ margin: '0 0 1rem', color: '#94A3B8', fontSize: '0.9rem' }}>
                            A UI rendering fault was contained before affecting backend governance state.
                        </p>
                        <pre
                            style={{
                                margin: '0 0 1rem',
                                padding: '0.75rem',
                                background: '#07090E',
                                borderRadius: '8px',
                                color: '#FECACA',
                                fontSize: '0.8rem',
                                overflowX: 'auto'
                            }}
                        >
                            {String(error?.message || error || 'Unexpected UI error')}
                        </pre>
                        <button
                            type="button"
                            onClick={reset}
                            style={{
                                background: '#10B981',
                                color: '#04130D',
                                border: 'none',
                                borderRadius: '8px',
                                padding: '0.55rem 1rem',
                                fontWeight: 700,
                                cursor: 'pointer'
                            }}
                        >
                            Reset Breaker Panel
                        </button>
                    </div>
                </div>
            )}
        >
            <BreakerCockpit />
        </ErrorBoundary>
    );
}
