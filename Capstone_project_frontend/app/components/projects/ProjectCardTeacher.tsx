'use client';

import Link from 'next/link';
import { BookOpen, CheckCircle2, Clock } from 'lucide-react';
import pdf from "../../../public/pdf.jpg";
import Image from "next/image";

interface Submission {
    id: number;
    project_id: number;
    student_id: number;
    file_name: string;
    file_url: string;
    submitted_at: string;
    phase: number;
}

interface File {
    id: number;
    project_id: number;
    file_name: string;
    file_url: string;
    file_type: string;
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
    final_deadline: string;
    state: 'active' | 'past';
}

interface ProjectCardProps {
    project: Project;
    role: string;
}

const ProjectCard: React.FC<ProjectCardProps> = ({ project }) => {
    const formatDate = (dateString: string) => {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    };

    const isCompleted = project.hasSubmittedPhase1 && project.hasSubmittedPhase2;
    // Determine status and styling based on project state and completion
    let status: string;
    let statusClass: string;

    if (isCompleted) {
        status = 'Completed';
        statusClass = 'bg-green-100 text-green-800';
    } else {
        status = project.state === 'past' ? 'Past' : 'Active';
        statusClass = project.state === 'past'
            ? 'bg-gray-100 text-gray-800'
            : 'bg-blue-100 text-blue-800';
    }
    const createdDate = formatDate(project.created_at);

    const phase1 = project.phase1Submission;
    const phase2 = project.phase2Submission;

    // Determine latest submission
    const latestSubmission = [phase1, phase2].reduce((latest, current) => {
        if (!current) return latest;
        if (!latest) return current;
        return new Date(current.submitted_at) > new Date(latest.submitted_at)
            ? current
            : latest;
    }, null as Submission | null);

    // Check if both phases are completed
    const submittedDate = latestSubmission
        ? formatDate(latestSubmission.submitted_at)
        : null;

    return (
        <Link href={`/projects/${project.id}`}>
            <div className="p-6 bg-white rounded-xl hover:bg-gray-50 transition-colors duration-300">
                <div className="flex flex-col md:flex-row justify-between">
                    <div className="flex-1">
                        <div className="flex items-center">
                            <BookOpen className="h-5 w-5 text-indigo-600 mr-2" />
                            <h3 className="text-xl font-semibold text-gray-800">{project.title}</h3>
                        </div>

                        <p className="mt-2 text-gray-600">{project.description}</p>

                        <div className="mt-4 grid gap-2">
                            <div className="flex items-center text-sm text-gray-500">
                                <Clock className="h-4 w-4 mr-1" />
                                <span>Created: {createdDate}</span>
                            </div>

                            {latestSubmission && submittedDate && (
                                <div className="flex items-center text-sm text-green-600">
                                    <CheckCircle2 className="h-4 w-4 mr-1" />
                                    <span>
                                        Submitted: {submittedDate} (Phase {latestSubmission.phase})
                                    </span>
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="mt-4 md:mt-0 md:ml-6 flex items-center">
                        <div className={`px-3 py-1 rounded-full text-sm font-medium ${statusClass}`}>
                            {status}
                        </div>
                    </div>
                </div>

                {project.files.length > 0 && (
                    <div className="mt-4 bg-gray-50 p-3 rounded">
                        <div className="flex items-center space-x-4">
                            <div className="relative w-16 h-20 flex-shrink-0">
                                <Image
                                    src={pdf}
                                    alt={project.title}
                                    fill
                                    className="object-contain bg-white"
                                    priority
                                />
                            </div>
                            <div>
                                <p className="text-sm font-medium text-gray-700 mb-2">Attached Files:</p>
                                <div className="space-y-1">
                                    {project.files.slice(0, 2).map((file) => (
                                        <div key={file.id} className="text-sm text-gray-600">
                                            {file.file_name}
                                        </div>
                                    ))}
                                    {project.files.length > 2 && (
                                        <div className="text-sm text-indigo-600">
                                            + {project.files.length - 2} more files
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </Link>
    );
};

export default ProjectCard;
