

// "use client";

// import { useState } from 'react';
// import { projectsApi } from '@/app/api/api'; // This import was missing

// interface FileUploadProps {
//     onFileSelect?: (file: File | null) => void;
//     projectId?: string; // Optional: For when updating an existing project
// }

// export default function FileUpload({ onFileSelect, projectId }: FileUploadProps) {
//     const [file, setFile] = useState<File | null>(null);
//     const [uploading, setUploading] = useState(false);
//     const [error, setError] = useState<string | null>(null);
//     const [success, setSuccess] = useState(false);

//     const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
//         const selectedFile = e.target.files?.[0] || null;

//         // Validate the file is a PDF
//         if (selectedFile && selectedFile.type !== 'application/pdf') {
//             setError('Only PDF files are allowed.');
//             setFile(null);
//             if (onFileSelect) onFileSelect(null);
//             return;
//         }

//         setFile(selectedFile);
//         setError(null);

//         // Notify parent component if callback is provided
//         if (onFileSelect) onFileSelect(selectedFile);
//     };

//     const handleUpload = async () => {
//         if (!file || !projectId) return;

//         setUploading(true);
//         setError(null);

//         try {
//             const formData = new FormData();
//             formData.append('file', file);
//             formData.append('fileType', 'problem_statement');

//             await projectsApi.uploadProjectFile(projectId, formData);

//             setSuccess(true);
//             setTimeout(() => setSuccess(false), 3000);
//         } catch (err) {
//             console.error('Error uploading file', err);
//             setError('Failed to upload file. Please try again.');
//         } finally {
//             setUploading(false);
//         }
//     };

//     return (
//         <div className="my-4">
//             <div className="border-2 border-dashed border-gray-300 rounded-md p-6">
//                 <input
//                     type="file"
//                     onChange={handleFileChange}
//                     accept=".pdf"
//                     className="hidden"
//                     id="file-upload"
//                 />
//                 <label
//                     htmlFor="file-upload"
//                     className="flex flex-col items-center justify-center cursor-pointer"
//                 >
//                     <svg
//                         className="w-12 h-12 text-gray-400"
//                         fill="none"
//                         stroke="currentColor"
//                         viewBox="0 0 24 24"
//                         xmlns="http://www.w3.org/2000/svg"
//                     >
//                         <path
//                             strokeLinecap="round"
//                             strokeLinejoin="round"
//                             strokeWidth="2"
//                             d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
//                         ></path>
//                     </svg>
//                     <p className="mt-2 text-sm text-gray-600">
//                         {file ? file.name : 'Click to select PDF file'}
//                     </p>
//                 </label>
//             </div>

//             {file && projectId && (
//                 <button
//                     onClick={handleUpload}
//                     disabled={uploading}
//                     className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-blue-300"
//                 >
//                     {uploading ? 'Uploading...' : 'Upload File'}
//                 </button>
//             )}

//             {error && <p className="text-red-500 mt-2">{error}</p>}
//             {success && <p className="text-green-500 mt-2">File uploaded successfully!</p>}
//         </div>
//     );
// }


"use client";

import { useState } from 'react';
import { projectsApi } from '@/app/api/api'; // Make sure this import is correct

interface FileUploadProps {
    onFileSelect: (file: File | null) => void;
    projectId?: string;
    directUpload?: boolean;
}

export default function FileUpload({ onFileSelect, projectId, directUpload = false }: FileUploadProps) {
    const [file, setFile] = useState<File | null>(null);
    const [uploading, setUploading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState(false);

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0] || null;

        // Validate file
        if (selectedFile && selectedFile.type !== 'application/pdf') {
            setError('Only PDF files are allowed');
            setFile(null);
            return;
        }

        setFile(selectedFile);
        setError(null);

        // Notify parent component
        onFileSelect(selectedFile);

        // If direct upload is enabled and we have a projectId, upload immediately
        if (directUpload && selectedFile && projectId) {
            // await handleUpload(selectedFile);
        }
    };

    const handleUpload = async (selectedFile: File | null = null) => {
        const fileToUpload = selectedFile || file;

        if (!fileToUpload || !projectId) {
            return;
        }

        setUploading(true);
        setError(null);

        try {
            const formData = new FormData();
            formData.append('file', fileToUpload);
            formData.append('fileType', 'problem_statement');

            console.log('Uploading file to project:', projectId);
            const result = await projectsApi.uploadProjectFile(projectId, formData);
            console.log('Upload result:', result);

            setSuccess(true);
            setTimeout(() => setSuccess(false), 3000);
        } catch (err: any) {
            console.error('Error uploading file:', err);
            setError(err.message || 'Failed to upload file');
        } finally {
            setUploading(false);
        }
    };

    return (
        <div className="my-4">
            <div className="border-2 border-dashed border-gray-300 rounded-md p-6">
                <input
                    type="file"
                    onChange={handleFileChange}
                    accept=".pdf"
                    className="hidden"
                    id="file-upload"
                />
                <label
                    htmlFor="file-upload"
                    className="flex flex-col items-center justify-center cursor-pointer"
                >
                    <svg
                        className="w-12 h-12 text-gray-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                        xmlns="http://www.w3.org/2000/svg"
                    >
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="2"
                            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                        ></path>
                    </svg>
                    <p className="mt-2 text-sm text-gray-600">
                        {file ? file.name : 'Click to select PDF file'}
                    </p>
                </label>
            </div>

            {file && projectId && !directUpload && (
                <button
                    onClick={() => handleUpload()}
                    disabled={uploading}
                    className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-blue-300"
                >
                    {uploading ? 'Uploading...' : 'Upload File'}
                </button>
            )}

            {error && <p className="text-red-500 mt-2">{error}</p>}
            {success && !directUpload && <p className="text-green-500 mt-2">File uploaded successfully!</p>}
            {uploading && <p className="text-blue-500 mt-2">Uploading file...</p>}
        </div>
    );
}