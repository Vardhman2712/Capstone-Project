'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { projectsApi } from '@/app/api/api';
import ProjectCard from '@/app/components/projects/ProjectCardTeacher';
import { FileText, FolderOpen, UploadCloud, CheckCircle2, Clock4, Plus } from 'lucide-react';
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';
import { useRouter } from 'next/navigation';

interface File {
  id: number;
  project_id: number;
  file_name: string;
  file_url: string;
  file_type: string;
}

interface Submission {
  id: number;
  student_id: number;
  phase: number;
  file_name: string;
  file_url: string;
  submitted_at: string;
  final_deadline: string;
}

interface Project {
  id: number;
  title: string;
  description: string;
  created_at: string;
  files: File[];
  submissions: Submission[];
  final_deadline: string;
  hasSubmittedPhase1: boolean;
  hasSubmittedPhase2: boolean;
  completeSubmissionCount: number;
  state: 'active' | 'past';
  first_deadline: string;
}

const TeacherDashboard = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { isApproved, isLoading: approvalLoading } = useApprovalStatus();
  const router = useRouter();

  useEffect(() => {
    if (isApproved === false) {
      router.push('/pending-approval');
      return;
    }

    if (isApproved === true) {
      fetchProjects();
    }
  }, [isApproved, router]);

  const fetchProjects = async () => {
    try {
      setIsLoading(true);
      const data = await projectsApi.getAllProjects();
      setProjects(data.projects || []);
    } catch (err) {
      setError('Failed to load projects');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  // Filter projects by state only
  const activeProjects = projects.filter(p => p.state === 'active' || !p.state);
  const pastProjects = projects.filter(p => p.state === 'past');

  // Count stats
  const countActiveProjects = () => activeProjects.length;
  const countPastProjects = () => pastProjects.length;
  const countFilesUploaded = () => projects.reduce((sum, project) => sum + project.files.length, 0);
  const countTotalSubmissions = () => projects.reduce((sum, project) => sum + (project.completeSubmissionCount || 0), 0);

  if (approvalLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Teacher Dashboard</h1>
        <Link
          href="/projects/create"
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg flex items-center gap-2"
        >
          <Plus className="w-5 h-5" />
          Create Project
        </Link>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-indigo-100 p-3 rounded-lg">
              <FolderOpen className="w-6 h-6 text-indigo-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Active Projects</p>
              <p className="text-2xl font-bold text-gray-900">{countActiveProjects()}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-purple-100 p-3 rounded-lg">
              <Clock4 className="w-6 h-6 text-purple-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Past Projects</p>
              <p className="text-2xl font-bold text-gray-900">{countPastProjects()}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-green-100 p-3 rounded-lg">
              <CheckCircle2 className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Total Submissions</p>
              <p className="text-2xl font-bold text-gray-900">{countTotalSubmissions()}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-blue-100 p-3 rounded-lg">
              <UploadCloud className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Files Uploaded</p>
              <p className="text-2xl font-bold text-gray-900">{countFilesUploaded()}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Active Projects */}
      {activeProjects.length > 0 && (
        <div className="mb-12">
          <h2 className="text-2xl font-semibold mb-6 text-gray-800 flex items-center gap-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            Active Projects
          </h2>
          <div className="grid grid-cols-1 gap-6">
            {activeProjects.map((project) => (
              <div key={project.id} className="bg-white border rounded-xl shadow-sm hover:shadow-md transition-all duration-300">
                <ProjectCard project={project} role="teacher" />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Past Projects */}
      {pastProjects.length > 0 && (
        <div className="mb-12">
          <h2 className="text-2xl font-semibold mb-6 text-gray-800 flex items-center gap-2">
            <div className="w-2 h-2 bg-gray-500 rounded-full"></div>
            Past Projects
          </h2>
          <div className="grid grid-cols-1 gap-6">
            {pastProjects.map((project) => (
              <div key={project.id} className="bg-white border rounded-xl shadow-sm hover:shadow-md transition-all duration-300 opacity-75">
                <ProjectCard project={project} role="teacher" />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Projects Message */}
      {projects.length === 0 && !isLoading && (
        <div className="text-center py-12 bg-gray-50 rounded-lg">
          <h3 className="text-xl font-medium text-gray-700 mb-2">No Projects Yet</h3>
          <p className="text-gray-600 mb-6">Get started by creating your first capstone project</p>
          <Link
            href="/projects/create"
            className="bg-indigo-600 hover:bg-indigo-700 text-white py-2 px-6 rounded-md inline-flex items-center gap-2"
          >
            <Plus className="w-5 h-5" />
            Create Project
          </Link>
        </div>
      )}
    </div>
  );
};

export default TeacherDashboard;
