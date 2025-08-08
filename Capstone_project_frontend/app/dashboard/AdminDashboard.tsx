'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { adminApi } from '@/app/api/api';

interface User {
    id: string;
    username: string;
    email: string;
    role: string;
    created_at: string;
    is_approved: boolean;
}

interface DashboardStats {
    totalUsers: number;
    approvedUsers: number;
    pendingUsers: number;
    roleStats: {
        [key: string]: number;
    };
}

export default function AdminDashboard() {
    const { user } = useAuth();
    const [users, setUsers] = useState<User[]>([]);
    const [stats, setStats] = useState<DashboardStats>({
        totalUsers: 0,
        approvedUsers: 0,
        pendingUsers: 0,
        roleStats: {}
    });
    const [activeTab, setActiveTab] = useState<'pending' | 'approved'>('pending');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Fetch dashboard data
    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                setLoading(true);
                setError(null);

                // Fetch stats
                const statsResponse = await adminApi.getDashboardStats();
                setStats(statsResponse);

                // Fetch users
                const usersResponse = await adminApi.getAllUsers();
                setUsers(usersResponse.users || []);
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data');
                console.error('Error fetching dashboard data:', err);
            } finally {
                setLoading(false);
            }
        };

        fetchDashboardData();
    }, []);

    // Handle user approval/rejection
    const handleUserApproval = async (userId: string, approve: boolean) => {
        try {
            await adminApi.updateUserApproval(userId, approve);

            // Update users list
            setUsers(prevUsers =>
                prevUsers.map(user =>
                    user.id === userId
                        ? { ...user, is_approved: approve }
                        : user
                )
            );

            // Update stats
            setStats(prevStats => ({
                ...prevStats,
                approvedUsers: prevStats.approvedUsers + (approve ? 1 : -1),
                pendingUsers: prevStats.pendingUsers + (approve ? -1 : 1)
            }));

            alert(`User ${approve ? 'approved' : 'access revoked'} successfully`);
        } catch (err) {
            console.error('Error updating user approval:', err);
            alert('Failed to update user access');
        }
    };

    const filteredUsers = users.filter(user =>
        activeTab === 'pending' ? !user.is_approved : user.is_approved
    );

    if (loading) {
        return <div className="flex justify-center items-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
        </div>;
    }

    if (error) {
        return <div className="text-red-600 p-4 bg-red-50 rounded-lg">{error}</div>;
    }

    return (
        <div className="space-y-6 p-6">
            {/* Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-700">Total Users</h3>
                    <p className="text-3xl font-bold text-indigo-600">{stats.totalUsers}</p>
                </div>
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-700">Approved Users</h3>
                    <p className="text-3xl font-bold text-green-600">{stats.approvedUsers}</p>
                </div>
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-700">Pending Users</h3>
                    <p className="text-3xl font-bold text-orange-600">{stats.pendingUsers}</p>
                </div>
            </div>

            {/* Role Statistics */}
            <div className="bg-white rounded-lg shadow-md p-6 mb-6">
                <h3 className="text-lg font-semibold text-gray-700 mb-4">Users by Role</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(stats.roleStats).map(([role, count]) => (
                        <div key={role} className="bg-gray-50 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-gray-500 uppercase">{role}</h4>
                            <p className="text-2xl font-bold text-indigo-600">{count}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* User Management Section */}
            <div className="bg-white rounded-lg shadow-md overflow-hidden">
                <div className="px-6 py-4 bg-indigo-600">
                    <h2 className="text-xl font-bold text-white">User Access Management</h2>
                </div>

                {/* Tab Navigation */}
                <div className="border-b border-gray-200">
                    <nav className="flex -mb-px">
                        <button
                            onClick={() => setActiveTab('pending')}
                            className={`py-4 px-6 text-center border-b-2 font-medium text-sm ${activeTab === 'pending'
                                ? 'border-indigo-500 text-indigo-600'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                }`}
                        >
                            Pending Approvals ({stats.pendingUsers})
                        </button>
                        <button
                            onClick={() => setActiveTab('approved')}
                            className={`py-4 px-6 text-center border-b-2 font-medium text-sm ${activeTab === 'approved'
                                ? 'border-indigo-500 text-indigo-600'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                }`}
                        >
                            Approved Users ({stats.approvedUsers})
                        </button>
                    </nav>
                </div>

                {filteredUsers.length === 0 ? (
                    <div className="p-6 text-center text-gray-500">
                        No {activeTab === 'pending' ? 'pending' : 'approved'} users
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Username</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Registration Date</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {filteredUsers.map((user) => (
                                    <tr key={user.id}>
                                        <td className="px-6 py-4 whitespace-nowrap">{user.username}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">{user.email}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                                                {user.role}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            {new Date(user.created_at).toLocaleDateString()}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            {user.is_approved ? (
                                                <button
                                                    onClick={() => handleUserApproval(user.id, false)}
                                                    className="bg-red-600 text-white px-3 py-1 rounded-md hover:bg-red-700 transition-colors"
                                                >
                                                    Revoke Access
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() => handleUserApproval(user.id, true)}
                                                    className="bg-green-600 text-white px-3 py-1 rounded-md hover:bg-green-700 transition-colors"
                                                >
                                                    Approve
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
} 