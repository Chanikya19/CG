import React from 'react';

export default function GlassCard({ children, className = '', glow = '' }) {
  let glowClass = '';
  if (glow === 'purple') glowClass = 'border-glow-purple';
  if (glow === 'emerald') glowClass = 'border-glow-emerald';
  if (glow === 'rose') glowClass = 'border-glow-rose';
  if (glow === 'blue') glowClass = 'border-glow-blue';
  if (glow === 'amber') glowClass = 'border-glow-amber';

  return (
    <div className={`glass-card rounded-2xl p-6 ${glowClass} ${className}`}>
      {children}
    </div>
  );
}
