import { Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import { loadBootstrap } from '@/lib/config';
import { AuthProvider } from '@/hooks/useAuth';
import { WeatherProvider } from '@/hooks/useWeather';
import Home from '@/pages/Home';
import PublicMessage from '@/pages/PublicMessage';
import Login from '@/pages/Login';
import Register from '@/pages/Register';
import VerifyEmail from '@/pages/VerifyEmail';
import Inbox from '@/pages/Inbox';
import Letter from '@/pages/Letter';
import Settings from '@/pages/Settings';

export default function App() {
  // 启动期拉取前端配置（应用名等）
  useEffect(() => {
    void loadBootstrap();
  }, []);

  return (
    <AuthProvider>
      <WeatherProvider>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/m/:unique_id" element={<PublicMessage />} />
          {/* /privacy-policy 与 /privacy-policy-cn 由后端 SSR 提供（静态法律文本） */}
          <Route path="/auth/login" element={<Login />} />
          <Route path="/auth/register" element={<Register />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/user/inbox" element={<Inbox />} />
          <Route path="/user/settings" element={<Settings />} />
          <Route path="/letters/:token" element={<Letter />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </WeatherProvider>
    </AuthProvider>
  );
}
