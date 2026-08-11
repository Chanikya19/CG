import React from 'react';

export default function GlassCard({ children, className = '', glow = '' }) {
  let glowClass = '';
  if (glow === 'purple') glowClass = 'border-glow-purple';
  if (glow === 'emerald') glowClass = 'border-glow-emerald';

  return (
    <div className={`glass-card rounded-2xl p-6 ${glowClass} ${className}`}>
      {children}
    </div>
  );
}
