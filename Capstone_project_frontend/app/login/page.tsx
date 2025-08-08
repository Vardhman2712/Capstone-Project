// app/login/page.tsx
import { Suspense } from 'react';
import LoginClient from '../components/auth/LoginClient';
import Loader from '../components/ui/Loader';

const LoginPage = () => {
    return (
        <Suspense fallback={<Loader variant="full-page" text="Loading your account..." />}>
            <LoginClient />
        </Suspense>
    );
};

export default LoginPage;