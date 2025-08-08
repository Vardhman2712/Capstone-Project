'use client';

import { useState, useEffect } from 'react';
import { managerApi } from '@/app/api/api';
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';
import { Clock4 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import {
    CheckCircle2,
    XCircle,
    UserPlus,
    FolderPlus,
    UserMinus,
    Users,
    Eye,
    Plus,
    Trash2,
    AlertCircle,
    BarChart3
} from 'lucide-react';
import { projectsApi } from '@/app/api/api';

interface StudentAccess {
    id: number;
    username: string;
    email: string;
    projects: Array<{
        project_id: number;
        title: string;
        status: string;
        approved_by: number;
        approved_by_username: string;
        approved_at: string;
    }>;
}

interface Student {
    id: number;
    username: string;
    email: string;
    created_at: string;
}

interface PendingProject {
    id: number;
    title: string;
    description: string;
    created_at: string;
    first_deadline: string;
    final_deadline: string;
    status: string;
    creator_name: string;
}

interface AccessSummary {
    projectSummary: Array<{
        project_id: number;
        title: string;
        status: string;
        created_at: string;
        students_with_access: number;
        total_students: number;
    }>;
    overallStats: {
        total_projects: number;
        students_with_any_access: number;
        approved_projects: number;
        pending_projects: number;
        total_students: number;
    };
}

const ManagerDashboard = () => {
    const [studentsWithAccess, setStudentsWithAccess] = useState<StudentAccess[]>([]);
    const [pendingProjects, setPendingProjects] = useState<PendingProject[]>([]);
    const [accessSummary, setAccessSummary] = useState<AccessSummary | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'pending' | 'access' | 'bulk' | 'summary'>('pending');
    const [showGrantModal, setShowGrantModal] = useState(false);
    const [modalStudentId, setModalStudentId] = useState<number | null>(null);
    const [selectedProject, setSelectedProject] = useState<number | null>(null);
    const [selectedStudents, setSelectedStudents] = useState<number[]>([]);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [projectToDelete, setProjectToDelete] = useState<number | null>(null);
    const [isDeleting, setIsDeleting] = useState(false);
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();
    const router = useRouter();

    const fetchDashboardData = async () => {
        try {
            setIsLoading(true);
            const [accessData, pendingData, summaryData] = await Promise.all([
                managerApi.getStudentsWithAccess(),
                managerApi.getPendingProjects(),
                managerApi.getAccessSummary(),
            ]);

            setStudentsWithAccess(accessData.students);
            setPendingProjects(pendingData.projects);
            setAccessSummary(summaryData);
        } catch (err) {
            setError('Failed to load dashboard data');
            console.error(err);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        if (isApproved) {
            fetchDashboardData();
        }
    }, [isApproved]);

    if (approvalLoading) {
        return (
            <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    if (!isApproved) {
        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
                <div className="max-w-md w-full space-y-8 text-center">
                    <div className="flex flex-col items-center">
                        <Clock4 className="h-12 w-12 text-indigo-600 mb-4" />
                        <h2 className="text-2xl font-bold text-gray-900">Account Pending Approval</h2>
                    </div>
                    <div className="mt-4 text-gray-600">
                        <p>Your account is currently pending approval from an administrator.</p>
                        <p className="mt-2">You will be able to access the dashboard once your account is approved.</p>
                    </div>
                    <div className="mt-4 text-sm text-gray-500">
                        <p>Please contact an administrator if you have any questions.</p>
                    </div>
                </div>
            </div>
        );
    }

    const handleApproveProject = async (projectId: number) => {
        try {
            await managerApi.approveProject({
                projectId: projectId.toString(),
                approvedStudentIds: selectedStudents.map(id => id.toString())
            });
            setPendingProjects(prev => prev.filter(p => p.id !== projectId));
            setSelectedStudents([]);
            await fetchDashboardData();
        } catch (err) {
            console.error('Approval failed:', err);
            setError('Failed to approve project');
        }
    };

    const handleGrantAccess = async (studentId: number, projectId: number) => {
        try {
            await managerApi.grantProjectAccess(
                studentId.toString(),
                projectId.toString()
            );
            await fetchDashboardData();
            setShowGrantModal(false);
        } catch (err) {
            console.error('Failed to grant access:', err);
            setError('Failed to grant project access');
        }
    };

    const handleRemoveAccess = async (studentId: number, projectId: number) => {
        try {
            await managerApi.removeProjectAccess(
                studentId.toString(),
                projectId.toString()
            );
            await fetchDashboardData();
        } catch (err) {
            console.error('Failed to remove access:', err);
            setError('Failed to remove project access');
        }
    };

    const handleBulkGrantAccess = async (projectId: number, studentIds: number[]) => {
        try {
            await managerApi.bulkGrantAccess(
                projectId.toString(),
                studentIds.map(id => id.toString())
            );
            await fetchDashboardData();
            setSelectedStudents([]);
            setSelectedProject(null);
        } catch (err) {
            console.error('Bulk grant failed:', err);
            setError('Failed to grant bulk access');
        }
    };

    const openGrantModal = (studentId: number) => {
        setModalStudentId(studentId);
        setShowGrantModal(true);
    };

    const getAvailableProjectsForStudent = (studentId: number) => {
        const student = studentsWithAccess.find(s => s.id === studentId);
        const studentProjectIds = student?.projects.map(p => p.project_id) || [];

        return accessSummary?.projectSummary.filter(
            p => p.status === 'approved' && !studentProjectIds.includes(p.project_id)
        ) || [];
    };

    const handleDeleteProject = async (projectId: number) => {
        setProjectToDelete(projectId);
        setShowDeleteModal(true);
    };

    const confirmDeleteProject = async () => {
        if (!projectToDelete) return;

        setIsDeleting(true);
        try {
            await projectsApi.deleteProject(projectToDelete.toString());

            // Update the projects list
            setPendingProjects(prev => prev.filter(p => p.id !== projectToDelete));

            // Refresh dashboard data
            await fetchDashboardData();

            setShowDeleteModal(false);
            setError(null);
        } catch (err) {
            console.error('Failed to delete project:', err);
            setError('Failed to delete project. Please try again.');
        } finally {
            setIsDeleting(false);
            setProjectToDelete(null);
        }
    };

    const TabButton = ({ tab, label, isActive, onClick }: {
        tab: string;
        label: string;
        isActive: boolean;
        onClick: () => void;
    }) => (
        <button
            onClick={onClick}
            className={`px-4 py-2 rounded-lg font-medium ${isActive
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
        >
            {label}
        </button>
    );

    if (isLoading) {
        return (
            <div className="p-6">
                <div className="flex justify-center py-12">
                    <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
                </div>
            </div>
        );
    }

    return (
        <div className="p-6 max-w-7xl mx-auto">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-800 mb-4">Manager Dashboard</h1>

                {/* Quick Stats */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div className="bg-blue-50 p-4 rounded-lg">
                        <div className="flex items-center">
                            <FolderPlus className="text-blue-600 w-6 h-6 mr-2" />
                            <div>
                                <p className="text-sm text-blue-600">Pending Projects</p>
                                <p className="text-xl font-bold text-blue-800">{pendingProjects.length}</p>
                            </div>
                        </div>
                    </div>
                    <div className="bg-green-50 p-4 rounded-lg">
                        <div className="flex items-center">
                            <CheckCircle2 className="text-green-600 w-6 h-6 mr-2" />
                            <div>
                                <p className="text-sm text-green-600">Total Students</p>
                                <p className="text-xl font-bold text-green-800">{accessSummary?.overallStats.total_students || 0}</p>
                            </div>
                        </div>
                    </div>
                    <div className="bg-purple-50 p-4 rounded-lg">
                        <div className="flex items-center">
                            <Users className="text-purple-600 w-6 h-6 mr-2" />
                            <div>
                                <p className="text-sm text-purple-600">Students w/ Access</p>
                                <p className="text-xl font-bold text-purple-800">
                                    {accessSummary?.overallStats.students_with_any_access || 0}
                                </p>
                            </div>
                        </div>
                    </div>
                    <div className="bg-orange-50 p-4 rounded-lg">
                        <div className="flex items-center">
                            <BarChart3 className="text-orange-600 w-6 h-6 mr-2" />
                            <div>
                                <p className="text-sm text-orange-600">Total Projects</p>
                                <p className="text-xl font-bold text-orange-800">
                                    {accessSummary?.overallStats.total_projects || 0}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Tab Navigation */}
                <div className="flex space-x-2 mb-6">
                    <TabButton
                        tab="pending"
                        label="Pending Approvals"
                        isActive={activeTab === 'pending'}
                        onClick={() => setActiveTab('pending')}
                    />
                    <TabButton
                        tab="access"
                        label="Student Access"
                        isActive={activeTab === 'access'}
                        onClick={() => setActiveTab('access')}
                    />
                    <TabButton
                        tab="bulk"
                        label="Bulk Management"
                        isActive={activeTab === 'bulk'}
                        onClick={() => setActiveTab('bulk')}
                    />
                    <TabButton
                        tab="summary"
                        label="Access Summary"
                        isActive={activeTab === 'summary'}
                        onClick={() => setActiveTab('summary')}
                    />
                </div>
            </div>

            {error && (
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4 flex items-center">
                    <AlertCircle className="w-5 h-5 mr-2" />
                    {error}
                    <button
                        onClick={() => setError(null)}
                        className="ml-auto text-red-500 hover:text-red-700"
                    >
                        ×
                    </button>
                </div>
            )}

            {/* Tab Content */}
            {activeTab === 'pending' && (
                <div>
                    <h2 className="text-2xl font-semibold mb-6 text-gray-800">
                        Pending Project Approvals
                    </h2>

                    {pendingProjects.length === 0 ? (
                        <div className="bg-green-50 p-8 rounded-lg text-center">
                            <CheckCircle2 className="w-16 h-16 text-green-600 mx-auto mb-4" />
                            <h3 className="text-lg font-semibold text-green-800 mb-2">All Clear!</h3>
                            <p className="text-green-700">No projects waiting for approval.</p>
                        </div>
                    ) : (
                        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                            {pendingProjects.map(project => (
                                <div key={project.id} className="border rounded-lg p-6 bg-white shadow-sm hover:shadow-md transition">
                                    <div className="mb-4">
                                        <h3 className="text-xl font-semibold mb-2">{project.title}</h3>
                                        <p className="text-gray-600 mb-2">{project.description}</p>
                                        <p className="text-sm text-gray-500">Created by: {project.creator_name}</p>
                                    </div>

                                    <div className="space-y-2 mb-6 text-sm">
                                        <div className="flex justify-between">
                                            <span className="text-gray-500">Phase 1 Deadline:</span>
                                            <span className="font-medium">
                                                {new Date(project.first_deadline).toLocaleDateString()}
                                            </span>
                                        </div>
                                        <div className="flex justify-between">
                                            <span className="text-gray-500">Final Deadline:</span>
                                            <span className="font-medium">
                                                {new Date(project.final_deadline).toLocaleDateString()}
                                            </span>
                                        </div>
                                        <div className="flex justify-between">
                                            <span className="text-gray-500">Submitted:</span>
                                            <span className="font-medium">
                                                {new Date(project.created_at).toLocaleDateString()}
                                            </span>
                                        </div>
                                    </div>

                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => handleApproveProject(project.id)}
                                            className="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded-md flex items-center justify-center transition-colors"
                                        >
                                            <CheckCircle2 className="w-5 h-5 mr-2" />
                                            Approve
                                        </button>
                                        <button
                                            onClick={() => handleDeleteProject(project.id)}
                                            className="bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-md flex items-center justify-center transition-colors"
                                        >
                                            <Trash2 className="w-5 h-5" />
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {activeTab === 'access' && (
                <div>
                    <h2 className="text-2xl font-semibold mb-6 text-gray-800">
                        Student Project Access Management
                    </h2>

                    <div className="bg-white rounded-lg shadow overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Student
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Project Access
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Actions
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {studentsWithAccess.map(student => (
                                        <tr key={student.id} className="hover:bg-gray-50">
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="flex items-center">
                                                    <div className="flex-shrink-0 h-10 w-10">
                                                        <div className="h-10 w-10 rounded-full bg-indigo-100 flex items-center justify-center">
                                                            <span className="text-indigo-600 font-medium text-sm">
                                                                {student.username.charAt(0).toUpperCase()}
                                                            </span>
                                                        </div>
                                                    </div>
                                                    <div className="ml-4">
                                                        <div className="text-sm font-medium text-gray-900">
                                                            {student.username}
                                                        </div>
                                                        <div className="text-sm text-gray-500">{student.email}</div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                {student.projects.length > 0 ? (
                                                    <div className="space-y-2">
                                                        {student.projects.map(project => (
                                                            <div key={project.project_id}
                                                                className="flex items-center justify-between bg-gray-50 p-2 rounded">
                                                                <div className="flex-1">
                                                                    <span className="text-sm font-medium">{project.title}</span>
                                                                    <div className="text-xs text-gray-500">
                                                                        Status: {project.status} |
                                                                        Approved by: {project.approved_by_username}
                                                                    </div>
                                                                </div>
                                                                <button
                                                                    onClick={() => handleRemoveAccess(student.id, project.project_id)}
                                                                    className="text-red-600 hover:text-red-800 p-1"
                                                                    title="Remove access"
                                                                >
                                                                    <Trash2 className="w-4 h-4" />
                                                                </button>
                                                            </div>
                                                        ))}
                                                    </div>
                                                ) : (
                                                    <span className="text-sm text-gray-500 italic">No project access</span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                <button
                                                    onClick={() => openGrantModal(student.id)}
                                                    className="text-indigo-600 hover:text-indigo-900 flex items-center"
                                                >
                                                    <Plus className="w-4 h-4 mr-1" />
                                                    Grant Access
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {activeTab === 'bulk' && (
                <div>
                    <h2 className="text-2xl font-semibold mb-6 text-gray-800">
                        Bulk Access Management
                    </h2>

                    <div className="bg-white rounded-lg shadow p-6">
                        <div className="space-y-6">
                            {/* Project Selection */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Select Project
                                </label>
                                <select
                                    value={selectedProject || ''}
                                    onChange={(e) => setSelectedProject(Number(e.target.value) || null)}
                                    className="w-full p-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
                                >
                                    <option value="">Choose a project...</option>
                                    {accessSummary?.projectSummary
                                        .filter(p => p.status === 'approved')
                                        .map(project => (
                                            <option key={project.project_id} value={project.project_id}>
                                                {project.title} ({project.students_with_access} students have access)
                                            </option>
                                        ))
                                    }
                                </select>
                            </div>

                            {/* Student Selection */}
                            {selectedProject && (
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Select Students
                                    </label>
                                    <div className="border border-gray-300 rounded-md max-h-60 overflow-y-auto">
                                        {accessSummary?.projectSummary
                                            .filter(p => p.project_id === selectedProject)
                                            .map(project => (
                                                <label key={project.project_id}
                                                    className={`flex items-center p-3 hover:bg-gray-50 ${selectedStudents.includes(project.project_id) ? 'opacity-50' : ''}`}>
                                                    <input
                                                        type="checkbox"
                                                        disabled={selectedStudents.includes(project.project_id)}
                                                        checked={selectedStudents.includes(project.project_id)}
                                                        onChange={(e) => {
                                                            if (e.target.checked) {
                                                                setSelectedStudents(prev => [...prev, project.project_id]);
                                                            } else {
                                                                setSelectedStudents(prev => prev.filter(id => id !== project.project_id));
                                                            }
                                                        }}
                                                        className="mr-3"
                                                    />
                                                    <div className="flex-1">
                                                        <div className="text-sm font-medium">{project.title}</div>
                                                        <div className="text-xs text-gray-500">
                                                            {project.students_with_access} students have access
                                                        </div>
                                                    </div>
                                                </label>
                                            ))}
                                    </div>
                                </div>
                            )}

                            {/* Bulk Actions */}
                            {selectedProject && selectedStudents.length > 0 && (
                                <div className="flex justify-between items-center pt-4 border-t">
                                    <span className="text-sm text-gray-600">
                                        {selectedStudents.length} student{selectedStudents.length !== 1 ? 's' : ''} selected
                                    </span>
                                    <div className="space-x-3">
                                        <button
                                            onClick={() => {
                                                setSelectedStudents([]);
                                                setSelectedProject(null);
                                            }}
                                            className="px-4 py-2 text-gray-600 hover:text-gray-800"
                                        >
                                            Clear Selection
                                        </button>
                                        <button
                                            onClick={() => handleBulkGrantAccess(selectedProject, selectedStudents)}
                                            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700"
                                        >
                                            Grant Access to Selected
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {activeTab === 'summary' && accessSummary && (
                <div>
                    <h2 className="text-2xl font-semibold mb-6 text-gray-800">
                        Access Summary & Statistics
                    </h2>

                    <div className="space-y-6">
                        {/* Overall Statistics */}
                        <div className="bg-white rounded-lg shadow p-6">
                            <h3 className="text-lg font-semibold mb-4">Overall Statistics</h3>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div className="text-center">
                                    <div className="text-3xl font-bold text-blue-600">
                                        {accessSummary.overallStats.total_projects}
                                    </div>
                                    <div className="text-sm text-gray-600">Total Projects</div>
                                </div>
                                <div className="text-center">
                                    <div className="text-3xl font-bold text-green-600">
                                        {accessSummary.overallStats.approved_projects}
                                    </div>
                                    <div className="text-sm text-gray-600">Approved Projects</div>
                                </div>
                                <div className="text-center">
                                    <div className="text-3xl font-bold text-purple-600">
                                        {Math.round((accessSummary.overallStats.students_with_any_access /
                                            accessSummary.overallStats.total_students) * 100)}%
                                    </div>
                                    <div className="text-sm text-gray-600">Students with Access</div>
                                </div>
                            </div>
                        </div>

                        {/* Project-wise Access */}
                        <div className="bg-white rounded-lg shadow overflow-hidden">
                            <div className="px-6 py-4 border-b border-gray-200">
                                <h3 className="text-lg font-semibold">Project Access Overview</h3>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Project
                                            </th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Status
                                            </th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Students with Access
                                            </th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Access Rate
                                            </th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Created
                                            </th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Actions
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {accessSummary.projectSummary.map(project => (
                                            <tr key={project.project_id} className="hover:bg-gray-50">
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="text-sm font-medium text-gray-900">
                                                        {project.title}
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${project.status === 'approved'
                                                        ? 'bg-green-100 text-green-800'
                                                        : project.status === 'pending_approval'
                                                            ? 'bg-yellow-100 text-yellow-800'
                                                            : 'bg-gray-100 text-gray-800'
                                                        }`}>
                                                        {project.status.replace('_', ' ')}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                                    {project.students_with_access} / {project.total_students}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="flex items-center">
                                                        <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                                                            <div
                                                                className="bg-indigo-600 h-2 rounded-full"
                                                                style={{
                                                                    width: `${(project.students_with_access / project.total_students) * 100}%`
                                                                }}
                                                            ></div>
                                                        </div>
                                                        <span className="text-xs text-gray-600">
                                                            {Math.round((project.students_with_access / project.total_students) * 100)}%
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    {new Date(project.created_at).toLocaleDateString()}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <div className="flex items-center space-x-2">
                                                        <button
                                                            onClick={() => handleDeleteProject(project.project_id)}
                                                            className="text-red-600 hover:text-red-900 p-1 rounded-full hover:bg-red-50 transition-colors"
                                                            title="Delete Project"
                                                        >
                                                            <Trash2 className="w-5 h-5" />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Grant Access Modal */}
            {showGrantModal && modalStudentId && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white rounded-lg p-6 w-full max-w-md">
                        <h3 className="text-lg font-semibold mb-4">Grant Project Access</h3>

                        <div className="space-y-4">
                            <p className="text-sm text-gray-600">
                                Select a project to grant access to:
                            </p>

                            <div className="max-h-60 overflow-y-auto space-y-2">
                                {getAvailableProjectsForStudent(modalStudentId).map(project => (
                                    <button
                                        key={project.project_id}
                                        onClick={() => handleGrantAccess(modalStudentId, project.project_id)}
                                        className="w-full text-left p-3 border border-gray-200 rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                    >
                                        <div className="font-medium">{project.title}</div>
                                        <div className="text-sm text-gray-500">
                                            {project.students_with_access} students have access
                                        </div>
                                    </button>
                                ))}
                            </div>

                            {getAvailableProjectsForStudent(modalStudentId).length === 0 && (
                                <p className="text-sm text-gray-600">
                                    No projects available for this student.
                                </p>
                            )}
                        </div>

                        <div className="flex justify-end mt-4">
                            <button
                                onClick={() => setShowGrantModal(false)}
                                className="px-4 py-2 text-gray-600 hover:text-gray-800"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Delete Project Confirmation Modal */}
            {showDeleteModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white rounded-lg p-6 w-full max-w-md">
                        <h3 className="text-lg font-semibold mb-4">Confirm Project Deletion</h3>
                        <p className="text-gray-600 mb-6">
                            Are you sure you want to delete this project? This action cannot be undone and will remove all associated data including submissions, reviews, and files.
                        </p>
                        <div className="flex justify-end space-x-4">
                            <button
                                onClick={() => {
                                    setShowDeleteModal(false);
                                    setProjectToDelete(null);
                                }}
                                className="px-4 py-2 text-gray-600 hover:text-gray-800"
                                disabled={isDeleting}
                            >
                                Cancel
                            </button>
                            <button
                                onClick={confirmDeleteProject}
                                className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 flex items-center"
                                disabled={isDeleting}
                            >
                                {isDeleting ? (
                                    <>
                                        <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white mr-2"></div>
                                        Deleting...
                                    </>
                                ) : (
                                    <>
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        Delete Project
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default ManagerDashboard;