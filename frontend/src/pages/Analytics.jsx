import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  RefreshCw, 
  TrendingUp, 
  ShieldCheck, 
  Lock, 
  Cpu, 
  Loader2 
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { auditAPI } from '../services/api';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function Analytics() {
  const [statsData, setStatsData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const data = await auditAPI.getStatistics();
      setStatsData(data);
    } catch (err) {
      console.error("Failed to load statistics data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="h-96 flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-8 h-8 text-purple-500 animate-spin" />
        <span className="text-xs uppercase tracking-widest text-gray-500">Retrieving security telemetry...</span>
      </div>
    );
  }

  // 1. Line Chart: Daily Uploads
  const lineData = {
    labels: statsData?.uploads_line.labels || [],
    datasets: [
      {
        label: 'File Uploads',
        data: statsData?.uploads_line.data || [],
        borderColor: '#a855f7',
        backgroundColor: 'rgba(168, 85, 247, 0.1)',
        fill: true,
        tension: 0.4,
        pointBackgroundColor: '#c084fc',
        pointBorderColor: '#000',
        pointHoverRadius: 6
      }
    ]
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0f172a',
        titleFont: { size: 10 },
        bodyFont: { size: 11 },
        borderWidth: 1,
        borderColor: '#334155'
      }
    },
    scales: {
      x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', font: { size: 9 } } },
      y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', font: { size: 9 }, stepSize: 1 } }
    }
  };

  // 2. Doughnut Chart: Integrity verified vs tampered
  const doughnutData = {
    labels: statsData?.integrity_doughnut.labels || [],
    datasets: [
      {
        data: statsData?.integrity_doughnut.data || [],
        backgroundColor: ['rgba(16, 185, 129, 0.85)', 'rgba(239, 68, 68, 0.85)'],
        borderColor: ['#10b981', '#ef4444'],
        borderWidth: 1.5,
        hoverOffset: 4
      }
    ]
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#94a3b8', boxWidth: 12, font: { size: 10 } }
      }
    }
  };

  // 3. Bar Chart: Key Algorithm usage
  const barData = {
    labels: statsData?.algorithms_bar.labels || [],
    datasets: [
      {
        label: 'Ciphers Usage',
        data: statsData?.algorithms_bar.data || [],
        backgroundColor: [
          'rgba(59, 130, 246, 0.75)',
          'rgba(99, 102, 241, 0.75)',
          'rgba(168, 85, 247, 0.75)'
        ],
        borderColor: ['#3b82f6', '#6366f1', '#a855f7'],
        borderWidth: 1.5,
        borderRadius: 8
      }
    ]
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    },
    scales: {
      x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 10 } } },
      y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', font: { size: 9 }, stepSize: 1 } }
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <BarChart3 className="w-8 h-8 text-purple-400" /> Cryptographic Analytics
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            Real-time analytics and statistics monitoring encryption algorithm usage, uploads, and data integrity.
          </p>
        </div>
        <button
          onClick={fetchStats}
          className="flex items-center gap-1.5 px-4 py-2 bg-white/5 hover:bg-white/10 border border-gray-800 rounded-xl text-xs font-semibold text-gray-300 transition-all active:scale-95"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Analytics
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Daily Uploads Line Chart */}
        <GlassCard className="lg:col-span-2 space-y-4" glow="purple">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-4.5 h-4.5 text-purple-400" /> Daily Document Uploads
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">Timeline of files vaulted in the platform over the last week.</p>
          </div>
          <div className="h-72">
            <Line data={lineData} options={lineOptions} />
          </div>
        </GlassCard>

        {/* Integrity status Doughnut */}
        <GlassCard className="space-y-4" glow="rose">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-4.5 h-4.5 text-emerald-400" /> Integrity Verification Audit
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">Proportion of verified intact files vs tampered alerts.</p>
          </div>
          <div className="h-72">
            <Doughnut data={doughnutData} options={doughnutData.datasets[0].data.reduce((a,b) => a+b, 0) > 0 ? doughnutOptions : {
              ...doughnutOptions,
              plugins: { ...doughnutOptions.plugins, legend: { display: true } }
            }} />
            {doughnutData.datasets[0].data.reduce((a,b) => a+b, 0) === 0 && (
              <div className="absolute inset-0 flex items-center justify-center text-xs text-gray-500 mt-6 select-none pointer-events-none">
                No integrity scans executed yet.
              </div>
            )}
          </div>
        </GlassCard>
      </div>

      {/* Algorithm usage bar chart */}
      <GlassCard className="space-y-4" glow="blue">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Cpu className="w-4.5 h-4.5 text-blue-400" /> Key wrap Algorithms Distribution
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">Utilization metrics of symmetric ciphers (AES-128, AES-256) and asymmetric ciphers (RSA).</p>
        </div>
        <div className="h-80">
          <Bar data={barData} options={barOptions} />
        </div>
      </GlassCard>
    </div>
  );
}
