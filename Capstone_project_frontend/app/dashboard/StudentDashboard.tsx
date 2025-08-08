'use client';

import { useState, useEffect } from 'react';
import ProjectCard from '@/app/components/projects/ProjectCard';
import { projectsApi } from '../api/api';
import { BookCheck, Clock4, BookOpen, FileText } from 'lucide-react';
import { useApprovalStatus } from '../hooks/useApprovalStatus';
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
  project_id: number;
  student_id: number;
  file_name: string;
  file_url: string;
  submitted_at: string;
  phase: number;
}

interface Project {
  id: number;
  title: string;
  description: string;
  created_at: string;
  files: File[];
  hasSubmittedPhase1: boolean;
  hasSubmittedPhase2: boolean;
  phase1Submission?: Submission;
  phase2Submission?: Submission;
  hasSubmitted?: boolean;
  state?: 'active' | 'past';
  first_deadline?: string;
  final_deadline?: string;
}

const StudentDashboard = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<{ type: string; message: string } | null>(null);
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
      const data = await projectsApi.getStudentProjects();
      const projectsData = (data.projects || []) as Project[];
      setProjects(projectsData);
    } catch (err) {
      setError({ type: 'fetch', message: 'Failed to load projects' });
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  // Filter projects by state and submission status
  const activeProjects = projects.filter(p => (p.state === 'active' || !p.state) && !p.hasSubmittedPhase2);
  const pastProjects = projects.filter(p => p.state === 'past' || p.hasSubmittedPhase2);

  if (approvalLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Student Dashboard</h1>
        <p className="mt-2 text-gray-600">Track your capstone project progress and submissions</p>
      </div>

      {/* Project Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-indigo-100 p-3 rounded-lg">
              <BookOpen className="w-6 h-6 text-indigo-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Active Projects</p>
              <p className="text-2xl font-bold text-gray-900">{activeProjects.length}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-green-100 p-3 rounded-lg">
              <BookCheck className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Completed Projects</p>
              <p className="text-2xl font-bold text-gray-900">
                {projects.filter(p => p.hasSubmittedPhase2).length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center gap-4">
            <div className="bg-purple-100 p-3 rounded-lg">
              <FileText className="w-6 h-6 text-purple-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Total Submissions</p>
              <p className="text-2xl font-bold text-gray-900">
                {projects.reduce((sum, p) => sum + (p.hasSubmittedPhase1 ? 1 : 0) + (p.hasSubmittedPhase2 ? 1 : 0), 0)}
              </p>
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
                <ProjectCard project={project} role="student" />
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
                <ProjectCard project={project} role="student" />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Projects Message */}
      {projects.length === 0 && !isLoading && (
        <div className="text-center py-12 bg-gray-50 rounded-lg">
          <h3 className="text-xl font-medium text-gray-700 mb-2">No Projects Available</h3>
          <p className="text-gray-600">
            You don't have any projects assigned yet. Please contact your teacher or coordinator.
          </p>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6">
          <p className="font-medium">Error loading projects</p>
          <p className="text-sm">{error.message}</p>
        </div>
      )}
    </div>
  );
};

export default StudentDashboard;
