'use client';

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Image from "next/image";
import Link from "next/link";
import pdf from "../../../public/pdf.jpg";
import {
    CheckCircle2,
    Clock,
    FileText,
    AlertCircle,
    Loader2,
    Upload,
    Download,
    Database,
    FolderOpen,
    Eye,
    X,
    File,
    Image as ImageIcon,
    FileSpreadsheet,
    Archive,
    AlarmClock,
    CalendarDays,
    Hourglass,
    Pencil,
    Save,
    Play
} from "lucide-react";
import { projectsApi } from "@/app/api/api";
import { useAuth } from "@/app/context/AuthContext";
import SubmissionForm from "@/app/components/projects/SubmissionForm";
import JSZip from 'jszip';
import { saveAs } from 'file-saver';
import PDFViewer from "@/app/components/pdf/pdfViewer";
import { toast } from "react-hot-toast";

interface File {
    id: number;
    file_name: string;
    file_url: string;
    file_type: string;
}

interface Submission {
    id: number;
    file_name: string;
    file_url: string;
    submitted_at: string;
    username: string;
    phase: number;
    student_id?: string;
    file_type: string;
}

interface Project {
    id: number;
    title: string;
    description: string;
    created_at: string;
    files: File[];
    phase1Submissions?: Submission[];
    phase2Submissions?: Submission[];
    first_deadline?: string;
    final_deadline?: string;
    phase1Submission?: Submission | null;
    phase2Submission?: Submission | null;
    phase1DeadlinePassed?: boolean;
    phase2DeadlinePassed?: boolean;
    reviews?: Array<{
        submission_phase: number;
        student_id: string;
        rating?: number;
        comments?: string;
        reviewer_name?: string;
    }>;
    state?: 'active' | 'past';
}

interface FilePreview {
    file: File;
    type: 'image' | 'csv' | 'json' | 'text' | 'pdf' | 'unknown';
    content?: string;
    error?: string;
}

// Add this interface for file handling
interface FileWithName extends File {
    name: string;
}

interface UploadFile extends Blob {
    name: string;
}

interface SelectedFiles {
    [key: string]: UploadFile | null;
}

interface DeadlineEditProps {
    project: Project;
    onUpdate: () => void;
}

const DeadlineEdit: React.FC<DeadlineEditProps> = ({ project, onUpdate }) => {
    const { user } = useAuth();
    const [isEditing, setIsEditing] = useState(false);
    const [firstDeadline, setFirstDeadline] = useState('');
    const [finalDeadline, setFinalDeadline] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    // Initialize deadlines when component mounts or project changes
    useEffect(() => {
        if (project.first_deadline) {
            const firstDate = new Date(project.first_deadline);
            setFirstDeadline(firstDate.toISOString().slice(0, 16));
        }
        if (project.final_deadline) {
            const finalDate = new Date(project.final_deadline);
            setFinalDeadline(finalDate.toISOString().slice(0, 16));
        }
    }, [project]);

    const canEditDeadlines = user && ['teacher', 'academic_team', 'coordinator', 'admin'].includes(user.role);

    const handleSave = async () => {
        try {
            setError(null);
            setLoading(true);

            if (!firstDeadline || !finalDeadline) {
                setError('Both deadlines are required');
                return;
            }

            // Convert to Date objects for validation
            const firstDate = new Date(firstDeadline);
            const finalDate = new Date(finalDeadline);

            if (isNaN(firstDate.getTime()) || isNaN(finalDate.getTime())) {
                setError('Invalid date format');
                return;
            }

            if (firstDate >= finalDate) {
                setError('First deadline must be before final deadline');
                return;
            }

            await projectsApi.updateProjectDeadlines(project.id.toString(), {
                firstDeadline: firstDate.toISOString(),
                finalDeadline: finalDate.toISOString()
            });

            setIsEditing(false);
            onUpdate();
            toast.success('Deadlines updated successfully');
        } catch (err: any) {
            console.error('Error updating deadlines:', err);
            setError(err.message || 'Failed to update deadlines');
            toast.error(err.message || 'Failed to update deadlines');
        } finally {
            setLoading(false);
        }
    };

    if (!canEditDeadlines) return null;

    return (
        <div className="mt-4">
            {!isEditing ? (
                <button
                    onClick={() => setIsEditing(true)}
                    className="flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                >
                    <Pencil size={14} className="sm:w-4 sm:h-4" />
                    <span>Edit Deadlines</span>
                </button>
            ) : (
                <div className="space-y-4 bg-white border border-gray-200 rounded-lg p-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                Phase 1 Deadline
                            </label>
                            <input
                                type="datetime-local"
                                value={firstDeadline}
                                onChange={(e) => setFirstDeadline(e.target.value)}
                                className="w-full border rounded-md px-3 py-2 focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                Final Deadline
                            </label>
                            <input
                                type="datetime-local"
                                value={finalDeadline}
                                onChange={(e) => setFinalDeadline(e.target.value)}
                                className="w-full border rounded-md px-3 py-2 focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
                                required
                            />
                        </div>
                    </div>
                    {error && (
                        <div className="text-sm text-red-600">{error}</div>
                    )}
                    <div className="flex justify-end gap-2">
                        <button
                            onClick={() => setIsEditing(false)}
                            className="px-3 py-2 text-sm text-gray-600 hover:text-gray-800"
                            disabled={loading}
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSave}
                            disabled={loading}
                            className="px-3 py-2 text-sm bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 flex items-center gap-2"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="h-4 w-4 animate-spin" />
                                    <span>Saving...</span>
                                </>
                            ) : (
                                <>
                                    <Save size={14} className="sm:w-4 sm:h-4" />
                                    <span>Save Changes</span>
                                </>
                            )}
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

interface ProjectStateProps {
    project: Project;
    onUpdate: () => void;
}

const ProjectState: React.FC<ProjectStateProps> = ({ project, onUpdate }) => {
    const { user } = useAuth();
    const [isUpdating, setIsUpdating] = useState(false);
    const [showDeadlineModal, setShowDeadlineModal] = useState(false);
    const [showConfirmModal, setShowConfirmModal] = useState(false);
    const [newDeadlines, setNewDeadlines] = useState({
        firstDeadline: '',
        finalDeadline: ''
    });

    const canManageState = user && ['teacher', 'academic_team', 'coordinator', 'admin'].includes(user.role);

    const handleStateChange = async (newState: 'active' | 'past') => {
        try {
            setIsUpdating(true);

            if (newState === 'past') {
                // Show confirmation modal instead of direct action
                setShowConfirmModal(true);
                setIsUpdating(false);
                return;
            } else if (newState === 'active') {
                // If current state is past or deadlines have passed, we need new deadlines
                const currentDate = new Date();
                const firstDeadlinePassed = project.first_deadline && new Date(project.first_deadline) < currentDate;
                const finalDeadlinePassed = project.final_deadline && new Date(project.final_deadline) < currentDate;

                if (project.state === 'past' || firstDeadlinePassed || finalDeadlinePassed) {
                    setShowDeadlineModal(true);
                } else {
                    await projectsApi.updateProjectState(project.id.toString(), {
                        state: 'active'
                    });
                    toast.success('Project marked as active');
                    onUpdate();
                }
            }
        } catch (error) {
            toast.error('Failed to update project state');
            console.error('Error updating project state:', error);
        } finally {
            setIsUpdating(false);
        }
    };

    const handleConfirmPastState = async () => {
        try {
            setIsUpdating(true);
            await projectsApi.updateProjectState(project.id.toString(), {
                state: 'past'
            });
            toast.success('Project marked as past');
            setShowConfirmModal(false);
            onUpdate();
        } catch (error) {
            toast.error('Failed to update project state');
            console.error('Error updating project state:', error);
        } finally {
            setIsUpdating(false);
        }
    };

    const handleDeadlineSubmit = async () => {
        try {
            // Parse dates for validation
            const firstDate = new Date(newDeadlines.firstDeadline);
            const finalDate = new Date(newDeadlines.finalDeadline);
            const now = new Date();

            // Validate dates
            if (isNaN(firstDate.getTime()) || isNaN(finalDate.getTime())) {
                toast.error('Please enter valid dates');
                return;
            }

            if (firstDate >= finalDate) {
                toast.error('First deadline must be before final deadline');
                return;
            }

            if (firstDate <= now) {
                toast.error('First deadline must be in the future');
                return;
            }

            if (finalDate <= now) {
                toast.error('Final deadline must be in the future');
                return;
            }

            setIsUpdating(true);
            await projectsApi.updateProjectState(project.id.toString(), {
                state: 'active',
                firstDeadline: newDeadlines.firstDeadline,
                finalDeadline: newDeadlines.finalDeadline
            });
            toast.success('Project activated with new deadlines');
            setShowDeadlineModal(false);
            onUpdate();
        } catch (error) {
            toast.error('Failed to update project state and deadlines');
            console.error('Error:', error);
        } finally {
            setIsUpdating(false);
        }
    };

    if (!canManageState) return null;

    return (
        <div className="mt-4">
            <div className="flex items-center gap-2">
                {project?.state === 'active' ? (
                    <button
                        onClick={() => handleStateChange('past')}
                        className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors flex items-center gap-2 font-medium shadow-sm"
                        disabled={isUpdating}
                    >
                        <Archive size={16} />
                        <span>Mark as Past Project</span>
                    </button>
                ) : (
                    <button
                        onClick={() => handleStateChange('active')}
                        className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors flex items-center gap-2 font-medium shadow-sm"
                        disabled={isUpdating}
                    >
                        <Play size={16} />
                        <span>Set as Active Project</span>
                    </button>
                )}
            </div>

            {/* Confirmation Modal for Past State */}
            {showConfirmModal && (
                <div className="fixed inset-0 flex items-center justify-center z-[1000] animate-fadeIn">
                    <div
                        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300"
                        onClick={() => setShowConfirmModal(false)}
                    />
                    <div className="bg-white rounded-xl p-8 max-w-md w-full mx-4 relative z-[1001] shadow-2xl border border-gray-100 transform transition-all duration-300 scale-100 animate-slideIn">
                        <div className="absolute top-4 right-4">
                            <button
                                onClick={() => setShowConfirmModal(false)}
                                className="text-gray-400 hover:text-gray-600 transition-colors"
                            >
                                <X className="h-5 w-5" />
                            </button>
                        </div>
                        <div className="flex items-center space-x-4 mb-6">
                            <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                                <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                            </div>
                            <h3 className="text-xl font-semibold text-gray-900">Mark Project as Past?</h3>
                        </div>
                        <div className="bg-red-50 rounded-lg p-4 mb-6">
                            <p className="text-sm text-red-800 font-medium mb-2">
                                This action will:
                            </p>
                            <ul className="space-y-2 text-sm text-red-700">
                                <li className="flex items-center">
                                    <div className="w-1.5 h-1.5 bg-red-500 rounded-full mr-2" />
                                    Stop accepting any new submissions
                                </li>
                                <li className="flex items-center">
                                    <div className="w-1.5 h-1.5 bg-red-500 rounded-full mr-2" />
                                    Keep all existing submissions unchanged
                                </li>
                                <li className="flex items-center">
                                    <div className="w-1.5 h-1.5 bg-red-500 rounded-full mr-2" />
                                    Mark the project as completed
                                </li>
                            </ul>
                        </div>
                        <div className="flex justify-end space-x-3">
                            <button
                                onClick={() => setShowConfirmModal(false)}
                                className="px-4 py-2 text-gray-700 hover:text-gray-900 font-medium transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleConfirmPastState}
                                className="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 font-medium transition-colors shadow-sm hover:shadow-md disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-w-[100px]"
                                disabled={isUpdating}
                            >
                                {isUpdating ? (
                                    <div className="flex items-center gap-2">
                                        <Loader2 className="h-4 w-4 animate-spin" />
                                        <span>Updating...</span>
                                    </div>
                                ) : (
                                    'Confirm'
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* New Deadlines Modal */}
            {showDeadlineModal && (
                <div className="fixed inset-0 flex items-center justify-center z-[1000] animate-fadeIn">
                    <div
                        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300"
                        onClick={() => setShowDeadlineModal(false)}
                    />
                    <div className="bg-white rounded-xl p-8 max-w-md w-full mx-4 relative z-[1001] shadow-2xl border border-gray-100 transform transition-all duration-300 scale-100 animate-slideIn">
                        <div className="absolute top-4 right-4">
                            <button
                                onClick={() => setShowDeadlineModal(false)}
                                className="text-gray-400 hover:text-gray-600 transition-colors"
                            >
                                <X className="h-5 w-5" />
                            </button>
                        </div>
                        <div className="flex items-center space-x-4 mb-6">
                            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                                <CalendarDays className="w-6 h-6 text-green-600" />
                            </div>
                            <h3 className="text-xl font-semibold text-gray-900">Set New Deadlines</h3>
                        </div>
                        <div className="space-y-6">
                            <div className="bg-green-50 rounded-lg p-4">
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-1">
                                            First Phase Deadline
                                        </label>
                                        <input
                                            type="datetime-local"
                                            className="w-full border border-gray-300 rounded-lg px-4 py-2.5 focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200 bg-white"
                                            value={newDeadlines.firstDeadline}
                                            onChange={(e) => setNewDeadlines(prev => ({
                                                ...prev,
                                                firstDeadline: e.target.value
                                            }))}
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-1">
                                            Final Phase Deadline
                                        </label>
                                        <input
                                            type="datetime-local"
                                            className="w-full border border-gray-300 rounded-lg px-4 py-2.5 focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200 bg-white"
                                            value={newDeadlines.finalDeadline}
                                            onChange={(e) => setNewDeadlines(prev => ({
                                                ...prev,
                                                finalDeadline: e.target.value
                                            }))}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="flex justify-end space-x-3 mt-6">
                            <button
                                onClick={() => setShowDeadlineModal(false)}
                                className="px-4 py-2 text-gray-700 hover:text-gray-900 font-medium transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleDeadlineSubmit}
                                className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 font-medium transition-colors shadow-sm hover:shadow-md disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-w-[140px]"
                                disabled={!newDeadlines.firstDeadline || !newDeadlines.finalDeadline || isUpdating}
                            >
                                {isUpdating ? (
                                    <div className="flex items-center gap-2">
                                        <Loader2 className="h-4 w-4 animate-spin" />
                                        <span>Updating...</span>
                                    </div>
                                ) : (
                                    'Activate Project'
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default function ProjectDetailsPage() {
    const [selectedPdf, setSelectedPdf] = useState<{
        file_name: string;
        file_url: string;
        file_type: string;
    } | null>(null);

    const [isImage, setIsImage] = useState(false);
    const [isPDF, setIsPDF] = useState(false);
    const [isZip, setIsZip] = useState(false);
    const [isCSV, setIsCSV] = useState(false);
    const [isTxt, setIsTxt] = useState(false);
    const [isCode, setIsCode] = useState(false);

    const { projectId } = useParams();
    const { user } = useAuth();
    const [project, setProject] = useState<Project | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [selectedFiles, setSelectedFiles] = useState<SelectedFiles>({
        problem_statement: null,
        dataset: null,
        additional_resource: null
    });
    const [showProjectDescription, setShowProjectDescription] = useState(true);

    const [uploadStatus, setUploadStatus] = useState<{
        loading: boolean;
        error: string | null;
        success: boolean;
        type?: string;
    }>({
        loading: false,
        error: null,
        success: false,
    });
    const [previewModal, setPreviewModal] = useState<{
        isOpen: boolean;
        file: File | null;
        preview: FilePreview | null;
    }>({
        isOpen: false,
        file: null,
        preview: null
    });


    useEffect(() => {
        const loadProject = async () => {
            try {
                setIsLoading(true);
                const data = await projectsApi.getProject(projectId as string);
                setProject(data.project);
            } catch (err) {
                console.error("Error loading project:", err);
                setError("Failed to load project details.");
            } finally {
                setIsLoading(false);
            }
        };

        if (projectId) {
            loadProject();
        }
    }, [projectId]);

    function truncateWords(str: string, limit: number): string {
        const words = str.split(/\s+/);
        if (words.length <= limit) return str;
        return words.slice(0, limit).join(" ") + "...";
    }


    const getFileIcon = (fileName: string, fileType: string) => {
        const extension = fileName.split('.').pop()?.toLowerCase();

        if (fileType === 'problem_statement' || extension === 'pdf') {
            return <FileText className="w-6 h-6 text-red-500" />;
        } else if (extension === 'csv' || extension === 'xlsx' || extension === 'xls') {
            return <FileSpreadsheet className="w-6 h-6 text-green-500" />;
        } else if (['jpg', 'jpeg', 'png', 'gif'].includes(extension || '')) {
            return <ImageIcon className="w-6 h-6 text-blue-500" />;
        } else if (extension === 'json') {
            return <Database className="w-6 h-6 text-yellow-500" />;
        } else if (extension === 'zip' || extension === 'rar') {
            return <Archive className="w-6 h-6 text-purple-500" />;
        } else {
            return <File className="w-6 h-6 text-gray-500" />;
        }
    };

    const getFileTypeLabel = (fileType: string) => {
        switch (fileType) {
            case 'problem_statement':
                return 'Problem Statement';
            case 'dataset':
                return 'Dataset';
            case 'additional_resource':
                return 'Additional Resource';
            default:
                return 'File';
        }
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, fileType: string) => {
        const file = e.target.files?.[0] || null;
        if (file) {
            setSelectedFiles(prev => ({
                ...prev,
                [fileType]: file as UploadFile
            }));
        }
        setUploadStatus({ loading: false, error: null, success: false });
    };

    const handleFileUpload = async (fileType: string) => {
        const file = selectedFiles[fileType];
        if (!file || !projectId) return;

        setUploadStatus({
            loading: true,
            error: null,
            success: false,
            type: fileType
        });

        try {
            const formData = new FormData();
            formData.append("file", file);
            formData.append("fileType", fileType);

            await projectsApi.uploadProjectFile(
                projectId as string,
                formData,
                fileType
            );

            const updated = await projectsApi.getProject(projectId as string);
            setProject(updated.project);

            setUploadStatus({
                loading: false,
                error: null,
                success: true,
                type: fileType
            });

            setTimeout(() => {
                setUploadStatus((prev) => ({ ...prev, success: false }));
            }, 3000);

            setSelectedFiles(prev => ({ ...prev, [fileType]: null }));
        } catch (err: any) {
            console.error("File upload failed", err);
            setUploadStatus({
                loading: false,
                error: err.message || "Failed to upload file",
                success: false,
                type: fileType
            });
        }
    };

    const getFileTypeFromName = (fileName: string) => {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';

        if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(extension)) {
            return 'image';
        } else if (extension === 'pdf') {
            return 'pdf';
        } else if (extension === 'zip' || extension === 'rar') {
            return 'zip';
        } else if (extension === 'csv' || extension === 'xlsx' || extension === 'xls') {
            return 'spreadsheet';
        } else if (extension === 'txt' || extension === 'md') {
            return 'text';
        } else if (['js', 'jsx', 'ts', 'tsx', 'json', 'html', 'css', 'py'].includes(extension)) {
            return 'code';
        }
        return 'unknown';
    };

    const handleFilePreview = (file: File | Submission) => {
        if (!file) return;

        const fileType = getFileTypeFromName(file.file_name);
        setSelectedPdf({
            file_name: file.file_name,
            file_url: file.file_url,
            file_type: file.file_type || 'submission'
        });

        // Reset all type flags
        setIsImage(false);
        setIsPDF(false);
        setIsZip(false);
        setIsCSV(false);
        setIsTxt(false);
        setIsCode(false);

        // Set appropriate flag based on file type
        switch (fileType) {
            case 'image':
                setIsImage(true);
                break;
            case 'pdf':
                setIsPDF(true);
                break;
            case 'zip':
                setIsZip(true);
                break;
            case 'spreadsheet':
                setIsCSV(true);
                break;
            case 'text':
                setIsTxt(true);
                break;
            case 'code':
                setIsCode(true);
                break;
        }
    };

    const formatDate = (dateString: string) => {
        if (!dateString) return "N/A";
        const date = new Date(dateString);
        return date.toLocaleDateString("en-US", {
            year: "numeric",
            month: "short",
            day: "numeric",
        });
    };

    const organizeFilesByType = (files: File[]) => {
        const organized = {
            problem_statement: files.filter(f => f.file_type === 'problem_statement'),
            dataset: files.filter(f => f.file_type === 'dataset'),
            additional_resource: files.filter(f => f.file_type === 'additional_resource')
        };
        return organized;
    };

    const canUploadFiles = () => {
        return ['teacher', 'academic_team', 'evaluator', 'manager', 'coordinator', 'admin'].includes(user?.role || '');
    };


    const downloadCSV = (content: string, filename: string) => {
        const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    // Add these handler functions in the component
    const handleDownloadAllSubmissions = async (phase: 'phase1' | 'phase2') => {
        try {
            const submissions = phase === 'phase1'
                ? project?.phase1Submissions
                : project?.phase2Submissions;

            if (!submissions || submissions.length === 0) {
                alert('No submissions to download');
                return;
            }

            const zip = new JSZip();
            const folder = zip.folder(`${project?.title}_${phase}_submissions`);

            for (const submission of submissions) {
                const response = await fetch(submission.file_url);
                const blob = await response.blob();
                folder?.file(submission.file_name, blob);
            }

            const content = await zip.generateAsync({ type: 'blob' });
            saveAs(content, `${project?.title}_${phase}_submissions.zip`);
        } catch (error) {
            console.error('Error downloading submissions:', error);
            alert('Failed to download submissions');
        }
    };



    const generatePhaseCSVContent = (project: Project, phase: 'phase1' | 'phase2') => {
        const isPhase1 = phase === 'phase1';
        const phaseNumber = isPhase1 ? 1 : 2;
        const submissions = isPhase1 ? project.phase1Submissions : project.phase2Submissions;
        const phaseDeadline = isPhase1 ? project.first_deadline : project.final_deadline;

        const headers = [
            'Project ID',
            'Project Title',
            'Project Description',
            'Project State',
            'Created At',
            `${isPhase1 ? 'First' : 'Final'} Phase Deadline`,
            'Student ID',
            'Student Name',
            'Student Email',
            `Phase ${phaseNumber} Submission Date`,
            `Phase ${phaseNumber} File Name`,
            `Phase ${phaseNumber} File URL`,
            'Submission Status',
            'Deadline Status',
            `Phase ${phaseNumber} Rating`,
            `Phase ${phaseNumber} Comments`,
            `Phase ${phaseNumber} Reviewer Name`,
            'Review Status',
            'Last Updated'
        ];

        const rows = submissions?.map(submission => {
            const review = project.reviews?.find(r =>
                r.submission_phase === phaseNumber &&
                r.student_id === submission.student_id
            );

            const submissionDate = new Date(submission.submitted_at);
            const deadlineDate = phaseDeadline ? new Date(phaseDeadline) : null;
            const isLate = deadlineDate ? submissionDate > deadlineDate : false;

            return [
                project.id,
                project.title,
                project.description.substring(0, 100) + '...',  // Truncate description
                project.state || 'active',
                formatDate(project.created_at),
                formatDate(phaseDeadline || ''),
                submission.student_id || 'N/A',
                submission.username,
                submission.username + '@university.edu',  // Example email format
                formatDate(submission.submitted_at),
                submission.file_name,
                submission.file_url,
                isLate ? 'Late Submission' : 'On Time',
                deadlineDate ? (isLate ? 'Past Deadline' : 'Within Deadline') : 'No Deadline Set',
                review?.rating?.toString() || 'Pending',
                review?.comments?.replace(/\n/g, ' ').replace(/,/g, ';') || 'No Comments',
                review?.reviewer_name || 'Not Reviewed',
                review ? 'Reviewed' : 'Pending Review',
                formatDate(new Date().toISOString())  // Current timestamp
            ];
        }) || [];

        // Add summary row
        const summaryRow = [
            'SUMMARY',
            `Total Submissions: ${submissions?.length || 0}`,
            `On-Time: ${submissions?.filter(s => new Date(s.submitted_at) <= (phaseDeadline ? new Date(phaseDeadline) : new Date())).length || 0}`,
            `Late: ${submissions?.filter(s => new Date(s.submitted_at) > (phaseDeadline ? new Date(phaseDeadline) : new Date())).length || 0}`,
            `Reviewed: ${project.reviews?.filter(r => r.submission_phase === phaseNumber).length || 0}`,
            `Pending Review: ${(submissions?.length || 0) - (project.reviews?.filter(r => r.submission_phase === phaseNumber).length || 0)}`,
            ...Array(13).fill('')  // Fill remaining columns
        ];

        // Add metadata row
        const metadataRow = [
            'METADATA',
            `Generated On: ${formatDate(new Date().toISOString())}`,
            `Phase: ${phaseNumber}`,
            `Project Status: ${project.state || 'active'}`,
            ...Array(15).fill('')  // Fill remaining columns
        ];

        return [metadataRow, [], headers, ...rows, [], summaryRow]
            .map(row => row.map(cell => {
                // Properly escape and quote cells containing commas or quotes
                const cellStr = String(cell).replace(/"/g, '""');
                return `"${cellStr}"`;
            }).join(','))
            .join('\n');
    };

    // Separate handlers for each phase
    const handleGeneratePhase1CSV = () => {
        if (!project) return;
        const csvContent = generatePhaseCSVContent(project, 'phase1');
        const filename = `${project.title}_phase1_report.csv`;
        downloadCSV(csvContent, filename);
    };

    const handleGeneratePhase2CSV = () => {
        if (!project) return;
        const csvContent = generatePhaseCSVContent(project, 'phase2');
        const filename = `${project.title}_phase2_report.csv`;
        downloadCSV(csvContent, filename);
    };

    const handleSubmissionPreview = (submission: Submission | null | undefined) => {
        if (!submission) return;
        handleFilePreview(submission);
    };

    if (isLoading) {
        return (
            <div className="min-h-[60vh] flex flex-col items-center justify-center">
                <Loader2 className="h-12 w-12 text-indigo-600 animate-spin mb-4" />
                <p className="text-gray-600 font-medium">Loading project details...</p>
            </div>
        );
    }

    if (error || !project) {
        return (
            <div className="max-w-xl mx-auto mt-8 p-6 bg-red-50 border-l-4 border-red-500 rounded-md shadow-sm">
                <div className="flex items-center">
                    <AlertCircle className="h-6 w-6 text-red-500 mr-3" />
                    <h3 className="text-lg font-medium text-red-800">Error Loading Project</h3>
                </div>
                <p className="mt-2 text-red-700">{error || "Project not found"}</p>
                <button
                    className="mt-4 px-4 py-2 bg-red-100 hover:bg-red-200 text-red-800 rounded-md transition-colors"
                    onClick={() => window.location.reload()}
                >
                    Retry
                </button>
            </div>
        );
    }

    const organizedFiles = organizeFilesByType(project.files || []);

    return (
        <div className="w-full min-h-screen relative flex flex-col lg:flex-row">
            {/* PDF Viewer - Full screen on mobile, half screen on desktop */}
            {selectedPdf && (
                <div
                    className={`fixed lg:sticky top-0 left-0 w-full lg:w-1/2 max-h-screen bg-white shadow-lg border-r border-gray-200 z-[100]
                    ${selectedPdf ? 'block' : 'hidden'}`}
                >
                    <div className="h-full w-full flex flex-col">
                        <div className="flex-shrink-0 p-2 border-b border-gray-200">
                            <button
                                onClick={() => {
                                    setSelectedPdf(null);
                                    setIsImage(false);
                                    setIsZip(false);
                                    setIsPDF(false);
                                }}
                                className="p-2 hover:bg-gray-100 rounded-full transition-colors float-right"
                            >
                                <X className="h-6 w-6 text-gray-600" />
                            </button>
                        </div>
                        <div className="flex-1 overflow-auto">
                            <PDFViewer
                                fileName={selectedPdf.file_name}
                                fileUrl={selectedPdf.file_url}
                                isOpen={!!selectedPdf}
                                onClose={() => {
                                    setSelectedPdf(null);
                                    setIsImage(false);
                                    setIsZip(false);
                                    setIsPDF(false);
                                }}
                                layout="inline"
                                isImage={isImage}
                                isZip={isZip}
                                isPDF={isPDF}
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Project Details Container */}
            <div className={`w-full ${selectedPdf ? 'lg:w-1/2' : 'w-full'} min-h-screen bg-gray-50 overflow-y-auto`}>
                <div className="max-w-full px-4 sm:px-6 lg:px-8 py-6">
                    {/* Hide project details on mobile when PDF is open */}
                    <div className={`${selectedPdf ? 'hidden lg:block' : 'block'}`}>
                        {/* Title & Dates Section */}
                        <div className="text-center space-y-3 mb-6 sm:mb-8">
                            <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-4xl font-extrabold text-gray-900 md:leading-tight mx-8 tracking-tight px-2">
                                {project.title}
                            </h1>

                            {/* Creation Date */}
                            <div className="flex justify-center items-center gap-2 text-gray-500 text-xs sm:text-sm">
                                <CalendarDays className="w-3 h-3 sm:w-4 sm:h-4" />
                                <span>Created On: {formatDate(project.created_at)}</span>
                            </div>

                            {/* Deadline Badges */}
                            <div className="flex flex-col sm:flex-row justify-center gap-2 sm:gap-4 mt-3 px-2">
                                {project.first_deadline && (
                                    <div className="flex items-center justify-center gap-2 px-3 sm:px-4 py-2 bg-indigo-100 text-indigo-700 font-medium text-xs sm:text-sm rounded-full shadow-sm border border-indigo-300">
                                        <Hourglass className="w-3 h-3 sm:w-4 sm:h-4" />
                                        <span className="whitespace-nowrap">Phase 1: {formatDate(project.first_deadline)}</span>
                                    </div>
                                )}
                                {project.final_deadline && (
                                    <div className="flex items-center justify-center gap-2 px-3 sm:px-4 py-2 bg-rose-100 text-rose-700 font-medium text-xs sm:text-sm rounded-full shadow-sm border border-rose-300">
                                        <AlarmClock className="w-3 h-3 sm:w-4 sm:h-4" />
                                        <span className="whitespace-nowrap">Phase 2: {formatDate(project.final_deadline)}</span>
                                    </div>
                                )}
                            </div>

                            {/* Add DeadlineEdit component */}
                            <div className="flex justify-center mt-4">
                                <DeadlineEdit project={project} onUpdate={async () => {
                                    const updated = await projectsApi.getProject(projectId as string);
                                    setProject(updated.project);
                                }} />
                            </div>

                            {/* Add ProjectState component */}
                            <div className="flex justify-center mt-4">
                                <ProjectState project={project} onUpdate={async () => {
                                    const updated = await projectsApi.getProject(projectId as string);
                                    setProject(updated.project);
                                }} />
                            </div>
                        </div>

                        {/* Description Section */}
                        <div className="border border-gray-200 rounded-xl sm:rounded-2xl shadow-md bg-white overflow-hidden mb-6 sm:mb-8">
                            <div className="p-4 sm:p-6 md:p-8">
                                <h2 className="text-lg sm:text-xl md:text-2xl font-semibold text-gray-800 flex items-center gap-2 mb-4">
                                    <span className="border-l-4 border-indigo-500 pl-2 sm:pl-3">Project Description</span>
                                </h2>
                                <p className="text-sm sm:text-base text-gray-700 leading-relaxed whitespace-pre-line">
                                    {project.description}
                                </p>
                            </div>
                        </div>

                        {/* Files Section */}
                        <div className="border border-gray-200 rounded-xl shadow-sm bg-white mb-6 sm:mb-8 overflow-hidden">
                            <div className="p-4 sm:p-6">
                                <h2 className="text-lg sm:text-xl font-bold text-gray-800 mb-4 sm:mb-6 flex items-center">
                                    <FolderOpen className="mr-2" size={18} />
                                    Project Files
                                </h2>

                                {/* Problem Statements */}
                                <div className="mb-6 sm:mb-8">
                                    <h3 className="text-base sm:text-lg font-semibold text-gray-700 mb-3 sm:mb-4 flex items-center">
                                        <FileText className="mr-2 text-red-500" size={16} />
                                        Problem Statements
                                    </h3>

                                    {organizedFiles.problem_statement.length > 0 ? (
                                        <div className="grid gap-3 mb-4">
                                            {organizedFiles.problem_statement.map((file) => (
                                                <div key={file.id} className="flex flex-col sm:flex-row sm:items-center p-3 sm:p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                                    <div className="flex items-center flex-1 min-w-0">
                                                        <div className="relative w-10 h-12 sm:w-12 sm:h-16 flex-shrink-0 mr-3 sm:mr-4 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                            <Image src={pdf} alt="File icon" fill className="object-contain p-1" />
                                                        </div>
                                                        <div className="flex-1 min-w-0">
                                                            {/* Mobile view */}
                                                            <div className="sm:hidden">
                                                                <p className="font-medium text-gray-900 text-sm line-clamp-1" title={file.file_name}>
                                                                    {file.file_name}
                                                                </p>
                                                            </div>
                                                            {/* Desktop view */}
                                                            <div className="hidden sm:block">
                                                                <p className="font-medium text-gray-900 text-base line-clamp-1" title={file.file_name}>
                                                                    {file.file_name}
                                                                </p>
                                                            </div>
                                                            <p className="text-xs sm:text-sm text-gray-500 mt-1">
                                                                {getFileTypeLabel(file.file_type)}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <div className="flex items-center space-x-2 flex-shrink-0">
                                                        <button
                                                            onClick={() => handleSubmissionPreview(file as Submission)}
                                                            className="flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                            title="Preview"
                                                        >
                                                            <Eye size={14} className="sm:w-4 sm:h-4" />
                                                            <span>Preview</span>
                                                        </button>
                                                        <Link
                                                            href={file.file_url}
                                                            target="_blank"
                                                            className="flex items-center px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm whitespace-nowrap"
                                                        >
                                                            <Download size={14} className="mr-1 sm:w-4 sm:h-4" />
                                                            Download
                                                        </Link>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-center mb-4">
                                            <FileText className="h-6 w-6 sm:h-8 sm:w-8 text-gray-400 mx-auto mb-2" />
                                            <p className="text-gray-600 text-xs sm:text-sm">No problem statements uploaded yet.</p>
                                        </div>
                                    )}

                                    {/* Upload Form for Problem Statements */}
                                    {canUploadFiles() && (
                                        <div className="border border-gray-200 rounded-lg p-3 sm:p-4 bg-gray-50">
                                            <h4 className="font-medium text-gray-800 mb-3 text-sm sm:text-base">Upload Problem Statement</h4>
                                            {!selectedFiles.problem_statement ? (
                                                <label htmlFor="problem_statement_upload" className="flex flex-col items-center justify-center w-full h-20 sm:h-24 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-white hover:bg-gray-50 transition-colors">
                                                    <Upload className="w-5 h-5 sm:w-6 sm:h-6 mb-2 text-gray-400" />
                                                    <p className="text-xs sm:text-sm text-gray-500 text-center px-2">Click to upload PDF</p>
                                                    <input
                                                        id="problem_statement_upload"
                                                        type="file"
                                                        className="hidden"
                                                        onChange={(e) => handleFileChange(e, 'problem_statement')}
                                                        accept=".pdf"
                                                    />
                                                </label>
                                            ) : (
                                                <div className="bg-white border border-gray-200 rounded-lg p-3">
                                                    <div className="flex items-center justify-between mb-3">
                                                        <div className="flex items-center flex-1 min-w-0">
                                                            {getFileIcon(selectedFiles.problem_statement.name || '', 'problem_statement')}
                                                            <span className="ml-2 text-xs sm:text-sm font-medium line-clamp-1" title={selectedFiles.problem_statement.name}>
                                                                {selectedFiles.problem_statement.name}
                                                            </span>
                                                        </div>
                                                        <button
                                                            onClick={() => setSelectedFiles(prev => ({ ...prev, problem_statement: null }))}
                                                            className="text-red-600 hover:text-red-800 ml-2 flex-shrink-0"
                                                        >
                                                            <X size={14} className="sm:w-4 sm:h-4" />
                                                        </button>
                                                    </div>
                                                    <button
                                                        onClick={() => handleFileUpload('problem_statement')}
                                                        disabled={uploadStatus.loading && uploadStatus.type === 'problem_statement'}
                                                        className="w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-md font-medium transition-colors disabled:opacity-50 text-sm"
                                                    >
                                                        {uploadStatus.loading && uploadStatus.type === 'problem_statement' ? (
                                                            <Loader2 className="h-4 w-4 mx-auto animate-spin" />
                                                        ) : (
                                                            'Upload'
                                                        )}
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Datasets */}
                                <div className="mb-6 sm:mb-8">
                                    <h3 className="text-base sm:text-lg font-semibold text-gray-700 mb-3 sm:mb-4 flex items-center">
                                        <Database className="mr-2 text-green-500" size={16} />
                                        Datasets
                                    </h3>

                                    {organizedFiles.dataset.length > 0 ? (
                                        <div className="grid gap-3 mb-4">
                                            {organizedFiles.dataset.map((file) => (
                                                <div key={file.id} className="flex flex-col sm:flex-row sm:items-center p-3 sm:p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                                    <div className="flex items-center flex-1 min-w-0">
                                                        <div className="flex-shrink-0 mr-3 sm:mr-4">
                                                            {getFileIcon(file.file_name, file.file_type)}
                                                        </div>
                                                        <div className="flex-1 min-w-0">
                                                            <p className="font-medium text-gray-900 truncate text-sm sm:text-base" title={file.file_name}>
                                                                {file.file_name}
                                                            </p>
                                                            <p className="text-xs sm:text-sm text-gray-500 mt-1">
                                                                {getFileTypeLabel(file.file_type)}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <div className="flex space-x-2 justify-end sm:justify-start">
                                                        <button
                                                            onClick={() => handleSubmissionPreview(file as Submission)}
                                                            className="flex items-center gap-2 px-3 py-2 bg-green-100 hover:bg-green-200 text-green-700 rounded-md transition-colors text-sm"
                                                            title="Preview"
                                                        >
                                                            <Eye size={14} className="sm:w-4 sm:h-4" />
                                                            <span>Preview</span>
                                                        </button>
                                                        <Link
                                                            href={file.file_url}
                                                            target="_blank"
                                                            className="flex items-center px-3 py-2 bg-green-100 hover:bg-green-200 text-green-700 rounded-md transition-colors text-sm"
                                                        >
                                                            <Download size={14} className="mr-1 sm:w-4 sm:h-4" />
                                                            Download
                                                        </Link>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-center mb-4">
                                            <Database className="h-6 w-6 sm:h-8 sm:w-8 text-gray-400 mx-auto mb-2" />
                                            <p className="text-gray-600 text-xs sm:text-sm">No datasets uploaded yet.</p>
                                        </div>
                                    )}

                                    {/* Upload Form for Datasets */}
                                    {canUploadFiles() && (
                                        <div className="border border-gray-200 rounded-lg p-3 sm:p-4 bg-gray-50">
                                            <h4 className="font-medium text-gray-800 mb-3 text-sm sm:text-base">Upload Dataset</h4>
                                            {!selectedFiles.dataset ? (
                                                <label htmlFor="dataset_upload" className="flex flex-col items-center justify-center w-full h-20 sm:h-24 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-white hover:bg-gray-50 transition-colors">
                                                    <Upload className="w-5 h-5 sm:w-6 sm:h-6 mb-2 text-gray-400" />
                                                    <p className="text-xs sm:text-sm text-gray-500 text-center px-2">Click to upload CSV, JSON, Excel, etc.</p>
                                                    <input
                                                        id="dataset_upload"
                                                        type="file"
                                                        className="hidden"
                                                        onChange={(e) => handleFileChange(e, 'dataset')}
                                                        accept=".csv,.json,.xlsx,.xls,.txt,.zip"
                                                    />
                                                </label>
                                            ) : (
                                                <div className="bg-white border border-gray-200 rounded-lg p-3">
                                                    <div className="flex items-center justify-between mb-3">
                                                        <div className="flex items-center flex-1 min-w-0">
                                                            {getFileIcon(selectedFiles.dataset.name, 'dataset')}
                                                            <span className="ml-2 text-xs sm:text-sm font-medium line-clamp-1" title={selectedFiles.dataset.name}>
                                                                {selectedFiles.dataset.name}
                                                            </span>
                                                        </div>
                                                        <button
                                                            onClick={() => setSelectedFiles(prev => ({ ...prev, dataset: null }))}
                                                            className="text-red-600 hover:text-red-800 ml-2 flex-shrink-0"
                                                        >
                                                            <X size={14} className="sm:w-4 sm:h-4" />
                                                        </button>
                                                    </div>
                                                    <button
                                                        onClick={() => handleFileUpload('dataset')}
                                                        disabled={uploadStatus.loading && uploadStatus.type === 'dataset'}
                                                        className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md font-medium transition-colors disabled:opacity-50 text-sm"
                                                    >
                                                        {uploadStatus.loading && uploadStatus.type === 'dataset' ? (
                                                            <Loader2 className="h-4 w-4 mx-auto animate-spin" />
                                                        ) : (
                                                            'Upload'
                                                        )}
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Additional Resources */}
                                <div className="mb-6">
                                    <h3 className="text-base sm:text-lg font-semibold text-gray-700 mb-3 sm:mb-4 flex items-center">
                                        <FolderOpen className="mr-2 text-purple-500" size={16} />
                                        Additional Resources
                                    </h3>

                                    {organizedFiles.additional_resource.length > 0 ? (
                                        <div className="grid gap-3 mb-4">
                                            {organizedFiles.additional_resource.map((file) => (
                                                <div key={file.id} className="flex flex-col sm:flex-row sm:items-center p-3 sm:p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                                    <div className="flex items-center flex-1 min-w-0">
                                                        <div className="flex-shrink-0 mr-3 sm:mr-4">
                                                            {getFileIcon(file.file_name, file.file_type)}
                                                        </div>
                                                        <div className="flex-1 min-w-0">
                                                            <p className="font-medium text-gray-900 truncate text-sm sm:text-base" title={file.file_name}>
                                                                {file.file_name}
                                                            </p>
                                                            <p className="text-xs sm:text-sm text-gray-500 mt-1">
                                                                {getFileTypeLabel(file.file_type)}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <div className="flex space-x-2 justify-end sm:justify-start">
                                                        <button
                                                            onClick={() => handleSubmissionPreview(file as Submission)}
                                                            className="flex items-center gap-2 px-3 py-2 bg-purple-100 hover:bg-purple-200 text-purple-700 rounded-md transition-colors text-sm"
                                                            title="Preview"
                                                        >
                                                            <Eye size={14} className="sm:w-4 sm:h-4" />
                                                            <span>Preview</span>
                                                        </button>
                                                        <Link
                                                            href={file.file_url}
                                                            target="_blank"
                                                            className="flex items-center px-3 py-2 bg-purple-100 hover:bg-purple-200 text-purple-700 rounded-md transition-colors text-sm"
                                                        >
                                                            <Download size={14} className="mr-1 sm:w-4 sm:h-4" />
                                                            Download
                                                        </Link>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-center mb-4">
                                            <FolderOpen className="h-6 w-6 sm:h-8 sm:w-8 text-gray-400 mx-auto mb-2" />
                                            <p className="text-gray-600 text-xs sm:text-sm">No additional resources uploaded yet.</p>
                                        </div>
                                    )}

                                    {/* Upload Form for Additional Resources */}
                                    {canUploadFiles() && (
                                        <div className="border border-gray-200 rounded-lg p-3 sm:p-4 bg-gray-50">
                                            <h4 className="font-medium text-gray-800 mb-3 text-sm sm:text-base">Upload Additional Resource</h4>
                                            {!selectedFiles.additional_resource ? (
                                                <label htmlFor="additional_resource_upload" className="flex flex-col items-center justify-center w-full h-20 sm:h-24 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-white hover:bg-gray-50 transition-colors">
                                                    <Upload className="w-5 h-5 sm:w-6 sm:h-6 mb-2 text-gray-400" />
                                                    <p className="text-xs sm:text-sm text-gray-500 text-center px-2">Click to upload any file type</p>
                                                    <input
                                                        id="additional_resource_upload"
                                                        type="file"
                                                        className="hidden"
                                                        onChange={(e) => handleFileChange(e, 'additional_resource')}
                                                    />
                                                </label>
                                            ) : (
                                                <div className="bg-white border border-gray-200 rounded-lg p-3">
                                                    <div className="flex items-center justify-between mb-3">
                                                        <div className="flex items-center flex-1 min-w-0">
                                                            {getFileIcon(selectedFiles.additional_resource.name, 'additional_resource')}
                                                            <span className="ml-2 text-xs sm:text-sm font-medium line-clamp-1" title={selectedFiles.additional_resource.name}>
                                                                {selectedFiles.additional_resource.name}
                                                            </span>
                                                        </div>
                                                        <button
                                                            onClick={() => setSelectedFiles(prev => ({ ...prev, additional_resource: null }))}
                                                            className="text-red-600 hover:text-red-800 ml-2 flex-shrink-0"
                                                        >
                                                            <X size={14} className="sm:w-4 sm:h-4" />
                                                        </button>
                                                    </div>
                                                    <button
                                                        onClick={() => handleFileUpload('additional_resource')}
                                                        disabled={uploadStatus.loading && uploadStatus.type === 'additional_resource'}
                                                        className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-md font-medium transition-colors disabled:opacity-50 text-sm"
                                                    >
                                                        {uploadStatus.loading && uploadStatus.type === 'additional_resource' ? (
                                                            <Loader2 className="h-4 w-4 mx-auto animate-spin" />
                                                        ) : (
                                                            'Upload'
                                                        )}
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Upload Status Messages */}
                                {uploadStatus.error && (
                                    <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
                                        <p className="text-red-800 text-sm">{uploadStatus.error}</p>
                                    </div>
                                )}
                                {uploadStatus.success && (
                                    <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-md">
                                        <p className="text-green-800 text-sm">{uploadStatus.success}</p>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Submissions Section */}
                        <div className="mb-8 sm:mb-12">
                            <h2 className="text-xl sm:text-2xl font-bold text-gray-800 mb-4 sm:mb-6 text-center">Student Submissions</h2>

                            {/* Phase 1 Submissions */}
                            <div className="mb-6 sm:mb-10 border border-gray-200 rounded-lg bg-white p-4 sm:p-6 shadow-sm">
                                <h3 className="text-lg sm:text-xl font-semibold mb-4">Phase 1 Submissions</h3>

                                {/* Phase 1 Submission */}
                                {user?.role === "student" && project.phase1Submission ? (
                                    <div className="grid gap-4">
                                        <div className="flex flex-col sm:flex-row sm:items-center justify-between border border-gray-300 rounded-lg p-3 sm:p-4 hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                            <div className="flex items-center space-x-3 sm:space-x-4 flex-1 min-w-0">
                                                <div className="relative w-10 h-12 sm:w-12 sm:h-16 flex-shrink-0 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                    <Image
                                                        src={pdf}
                                                        alt="Submission PDF"
                                                        fill
                                                        className="object-contain p-1"
                                                    />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="font-semibold text-gray-900 truncate text-sm sm:text-base" title={project.phase1Submission.file_name}>
                                                        {project.phase1Submission.file_name}
                                                    </p>
                                                    <p className="text-xs sm:text-sm text-gray-500">
                                                        Submitted on {formatDate(project.phase1Submission.submitted_at)}
                                                    </p>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={() => handleSubmissionPreview(project.phase1Submission)}
                                                    className="flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                    title="Preview"
                                                >
                                                    <Eye size={14} className="sm:w-4 sm:h-4" />
                                                    <span>Preview</span>
                                                </button>
                                                <Link
                                                    href={project.phase1Submission.file_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                >
                                                    <Download size={14} className="mr-1 sm:w-4 sm:h-4" />
                                                    <span>Download</span>
                                                </Link>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <>
                                        {project.phase1Submissions && project.phase1Submissions.length > 0 ? (
                                            <div className="grid gap-4">
                                                {project.phase1Submissions.map((submission) => (
                                                    <div key={submission.id} className="flex flex-col sm:flex-row sm:items-center justify-between border border-gray-300 rounded-lg p-3 sm:p-4 hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                                        <div className="flex items-center space-x-3 sm:space-x-4 flex-1 min-w-0">
                                                            <div className="relative w-10 h-12 sm:w-12 sm:h-16 flex-shrink-0 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                                <Image
                                                                    src={pdf}
                                                                    alt="Submission PDF"
                                                                    fill
                                                                    className="object-contain p-1"
                                                                />
                                                            </div>
                                                            <div className="flex-1 min-w-0">
                                                                <p className="font-semibold text-gray-900 line-clamp-1 text-sm sm:text-base" title={submission.file_name}>
                                                                    {submission.file_name}
                                                                </p>
                                                                <div className="flex flex-wrap gap-2 mt-1 text-xs sm:text-sm text-gray-500">
                                                                    <span>Submitted by {submission.username}</span>
                                                                    <span>•</span>
                                                                    <span>{formatDate(submission.submitted_at)}</span>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <button
                                                                onClick={() => handleSubmissionPreview(submission)}
                                                                className="flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                                title="Preview"
                                                            >
                                                                <Eye size={14} className="sm:w-4 sm:h-4" />
                                                                <span>Preview</span>
                                                            </button>
                                                            <Link
                                                                href={submission.file_url}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                className="flex items-center px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                            >
                                                                <Download size={14} className="mr-1 sm:w-4 sm:h-4" />
                                                                <span>Download</span>
                                                            </Link>
                                                        </div>
                                                    </div>
                                                ))}
                                                <div className="flex justify-between items-center mb-4">
                                                    {/* <h3 className="text-lg sm:text-xl font-semibold">Phase 1 Submissions</h3> */}
                                                    {['teacher', 'academic_team', 'admin'].includes(user?.role || '') && (
                                                        <div className="flex gap-2">
                                                            <button
                                                                onClick={() => handleDownloadAllSubmissions('phase1')}
                                                                className="px-3 py-1 bg-indigo-600 text-white rounded-md text-sm hover:bg-indigo-700 flex items-center gap-1"
                                                                disabled={!project?.phase1Submissions?.length}
                                                            >
                                                                <Download size={16} />
                                                                <span>Download All</span>
                                                            </button>
                                                            <button
                                                                onClick={() => handleGeneratePhase1CSV()}
                                                                className="px-3 py-1 bg-green-600 text-white rounded-md text-sm hover:bg-green-700 flex items-center gap-1"
                                                                disabled={!project?.phase1Submissions?.length}
                                                            >
                                                                <FileSpreadsheet size={16} />
                                                                <span>Generate CSV</span>
                                                            </button>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        ) : (
                                            <p className="text-gray-600 text-sm sm:text-base">No submissions for Phase 1 yet.</p>
                                        )}
                                    </>
                                )}

                                {/* Phase 1 Submission Form */}
                                {user?.role === "student" && !project.phase1Submission && !project.phase1DeadlinePassed && (
                                    <div className="mt-4 sm:mt-6">
                                        <SubmissionForm
                                            projectId={project.id}
                                            phase="phase1"
                                            projectState={project.state}
                                            onSubmissionSuccess={async () => {
                                                const updated = await projectsApi.getProject(projectId as string);
                                                setProject(updated.project);
                                            }}
                                        />
                                    </div>
                                )}

                                {/* Message if student already submitted */}
                                {user?.role === "student" && !!project.phase1Submission && (
                                    <p className="mt-4 text-green-700 font-medium text-sm sm:text-base">
                                        You have already submitted for Phase 1.
                                    </p>
                                )}

                                {/* Message if deadline has passed */}
                                {user?.role === "student" && !project.phase1Submission && project.phase1DeadlinePassed && (
                                    <p className="mt-4 text-red-600 font-medium text-sm sm:text-base">
                                        The deadline for Phase 1 has passed.
                                    </p>
                                )}
                            </div>

                            {/* Phase 2 Submissions */}
                            <div className="mb-6 sm:mb-10 border border-gray-200 rounded-lg bg-white p-4 sm:p-6 shadow-sm">
                                <h3 className="text-lg sm:text-xl font-semibold mb-4">Phase 2 Submissions</h3>

                                {/* Phase 2 Submission */}
                                {project.phase2Submission ? (
                                    <div className="grid gap-4">
                                        <div className="flex flex-col sm:flex-row sm:items-center justify-between border border-gray-300 rounded-lg p-3 sm:p-4 hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                            <div className="flex items-center space-x-3 sm:space-x-4 flex-1 min-w-0">
                                                <div className="relative w-10 h-12 sm:w-12 sm:h-16 flex-shrink-0 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                    <Image
                                                        src={pdf}
                                                        alt="Submission PDF"
                                                        fill
                                                        className="object-contain p-1"
                                                    />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="font-semibold text-gray-900 truncate text-sm sm:text-base">
                                                        {project.phase2Submission.file_name}
                                                    </p>
                                                    <p className="text-xs sm:text-sm text-gray-500">
                                                        Submitted on {formatDate(project.phase2Submission.submitted_at)}
                                                    </p>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={() => handleSubmissionPreview(project.phase2Submission)}
                                                    className="flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                    title="Preview"
                                                >
                                                    <Eye size={14} className="sm:w-4 sm:h-4" />
                                                    <span>Preview</span>
                                                </button>
                                                <a
                                                    href={project.phase2Submission.file_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center justify-center space-x-1 text-indigo-600 hover:text-indigo-800 bg-indigo-50 hover:bg-indigo-100 px-3 py-2 rounded-md transition-colors text-sm"
                                                >
                                                    <Download size={14} className="sm:w-4 sm:h-4" />
                                                    <span>Download</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <>
                                        {project.phase2Submissions && project.phase2Submissions.length > 0 ? (
                                            <div className="grid gap-4">
                                                {project.phase2Submissions.map((submission) => (
                                                    <div key={submission.id} className="flex flex-col sm:flex-row sm:items-center justify-between border border-gray-300 rounded-lg p-3 sm:p-4 hover:bg-gray-50 transition-colors space-y-3 sm:space-y-0">
                                                        <div className="flex items-center space-x-3 sm:space-x-4 flex-1 min-w-0">
                                                            <div className="relative w-10 h-12 sm:w-12 sm:h-16 flex-shrink-0 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                                <Image
                                                                    src={pdf}
                                                                    alt="Submission PDF"
                                                                    fill
                                                                    className="object-contain p-1"
                                                                />
                                                            </div>
                                                            <div className="flex-1 min-w-0">
                                                                <p className="font-semibold text-gray-900 truncate text-sm sm:text-base">
                                                                    {submission.file_name}
                                                                </p>
                                                                <p className="text-xs sm:text-sm text-gray-500">
                                                                    Submitted by {submission.username} on {formatDate(submission.submitted_at)}
                                                                </p>
                                                            </div>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <button
                                                                onClick={() => handleSubmissionPreview(submission)}
                                                                className="flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                                title="Preview"
                                                            >
                                                                <Eye size={14} className="sm:w-4 sm:h-4" />
                                                                <span>Preview</span>
                                                            </button>
                                                            <Link
                                                                href={submission.file_url}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                className="flex items-center px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm"
                                                            >
                                                                <Download size={14} className="mr-1 sm:w-4 sm:h-4" />
                                                                <span>Download</span>
                                                            </Link>
                                                        </div>
                                                    </div>
                                                ))}
                                                <div className="flex justify-between items-center mb-4">
                                                    {/* <h3 className="text-lg sm:text-xl font-semibold">Phase 2 Submissions</h3> */}
                                                    {['teacher', 'academic_team', 'admin'].includes(user?.role || '') && (
                                                        <div className="flex gap-2">
                                                            <button
                                                                onClick={() => handleDownloadAllSubmissions('phase2')}
                                                                className="px-3 py-1 bg-indigo-600 text-white rounded-md text-sm hover:bg-indigo-700 flex items-center gap-1"
                                                                disabled={!project?.phase2Submissions?.length}
                                                            >
                                                                <Download size={16} />
                                                                <span>Download All</span>
                                                            </button>
                                                            <button
                                                                onClick={() => handleGeneratePhase2CSV()}
                                                                className="px-3 py-1 bg-green-600 text-white rounded-md text-sm hover:bg-green-700 flex items-center gap-1"
                                                                disabled={!project?.phase2Submissions?.length}
                                                            >
                                                                <FileSpreadsheet size={16} />
                                                                <span>Generate CSV</span>
                                                            </button>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        ) : (
                                            <p className="text-gray-600 text-sm sm:text-base">No submissions for Phase 2 yet.</p>
                                        )}
                                    </>
                                )}

                                {/* Phase 2 Submission Form */}
                                {user?.role === "student" && !project.phase2Submission && project.phase1Submission && !project.phase2DeadlinePassed && (
                                    <div className="mt-4 sm:mt-6">
                                        <SubmissionForm
                                            projectId={project.id}
                                            phase="phase2"
                                            projectState={project.state}
                                            onSubmissionSuccess={async () => {
                                                const updated = await projectsApi.getProject(projectId as string);
                                                setProject(updated.project);
                                            }}
                                        />
                                    </div>
                                )}

                                {/* Message if student already submitted */}
                                {user?.role === "student" && !!project.phase2Submission && (
                                    <p className="mt-4 text-green-700 font-medium text-sm sm:text-base">
                                        You have already submitted for Phase 2.
                                    </p>
                                )}

                                {/* Message if student needs to submit Phase 1 first */}
                                {user?.role === "student" && !project.phase2Submission && !project.phase1Submission && !project.phase2DeadlinePassed && (
                                    <p className="mt-4 text-amber-600 font-medium">
                                        You must submit Phase 1 before you can submit Phase 2.
                                    </p>
                                )}

                                {/* Message if deadline has passed */}
                                {user?.role === "student" && !project.phase2Submission && project.phase2DeadlinePassed && (
                                    <p className="mt-4 text-red-600 font-medium">
                                        The deadline for Phase 2 has passed.
                                    </p>
                                )}
                            </div>
                        </div>

                    </div>
                </div>
            </div>
        </div>
    );
}