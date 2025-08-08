

// "use client";

// import { useState } from 'react';
// import { projectsApi } from '@/app/api/api'; // Make sure this import is correct

// interface FileUploadProps {
//     onFileSelect: (file: File | null) => void;
//     projectId?: string;
//     directUpload?: boolean;
// }

// export default function FileUpload({ onFileSelect, projectId, directUpload = false }: FileUploadProps) {
//     const [file, setFile] = useState<File | null>(null);
//     const [uploading, setUploading] = useState(false);
//     const [error, setError] = useState<string | null>(null);
//     const [success, setSuccess] = useState(false);

//     const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
//         const selectedFile = e.target.files?.[0] || null;

//         // Validate file
//         if (selectedFile && selectedFile.type !== 'application/pdf') {
//             setError('Only PDF files are allowed');
//             setFile(null);
//             return;
//         }

//         setFile(selectedFile);
//         setError(null);

//         // Notify parent component
//         onFileSelect(selectedFile);

//         // If direct upload is enabled and we have a projectId, upload immediately
//         if (directUpload && selectedFile && projectId) {
//             // await handleUpload(selectedFile);
//         }
//     };

//     const handleUpload = async (selectedFile: File | null = null) => {
//         const fileToUpload = selectedFile || file;

//         if (!fileToUpload || !projectId) {
//             return;
//         }

//         setUploading(true);
//         setError(null);

//         try {
//             const formData = new FormData();
//             formData.append('file', fileToUpload);
//             formData.append('fileType', 'problem_statement');

//             console.log('Uploading file to project:', projectId);
//             const result = await projectsApi.uploadProjectFile(projectId, formData);
//             console.log('Upload result:', result);

//             setSuccess(true);
//             setTimeout(() => setSuccess(false), 3000);
//         } catch (err: any) {
//             console.error('Error uploading file:', err);
//             setError(err.message || 'Failed to upload file');
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

//             {file && projectId && !directUpload && (
//                 <button
//                     onClick={() => handleUpload()}
//                     disabled={uploading}
//                     className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-blue-300"
//                 >
//                     {uploading ? 'Uploading...' : 'Upload File'}
//                 </button>
//             )}

//             {error && <p className="text-red-500 mt-2">{error}</p>}
//             {success && !directUpload && <p className="text-green-500 mt-2">File uploaded successfully!</p>}
//             {uploading && <p className="text-blue-500 mt-2">Uploading file...</p>}
//         </div>
//     );
// }


import { useState, useRef } from 'react';

export default function FileUpload({ onFileSelect, projectId, directUpload = false }) {
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);
    const [preview, setPreview] = useState(null);
    const [isDragging, setIsDragging] = useState(false);
    const fileInputRef = useRef(null);

    const handleFileChange = async (e) => {
        const selectedFile = e.target.files?.[0] || null;
        processFile(selectedFile);
    };

    const processFile = (selectedFile) => {
        // Validate file
        if (selectedFile && selectedFile.type !== 'application/pdf') {
            setError('Only PDF files are allowed');
            setFile(null);
            setPreview(null);
            return;
        }

        setFile(selectedFile);
        setError(null);

        // Create preview URL for PDF
        if (selectedFile) {
            const previewUrl = URL.createObjectURL(selectedFile);
            setPreview(previewUrl);
        } else {
            setPreview(null);
        }

        // Notify parent component
        onFileSelect(selectedFile);

        // If direct upload is enabled and we have a projectId, upload immediately
        if (directUpload && selectedFile && projectId) {
            // await handleUpload(selectedFile);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        setIsDragging(true);
    };

    const handleDragLeave = () => {
        setIsDragging(false);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setIsDragging(false);

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            processFile(e.dataTransfer.files[0]);
        }
    };

    const handleUpload = async (selectedFile = null) => {
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
            // const result = await projectsApi.uploadProjectFile(projectId, formData);
            // console.log('Upload result:', result);

            setSuccess(true);
            setTimeout(() => setSuccess(false), 3000);
        } catch (err) {
            console.error('Error uploading file:', err);
            setError(err.message || 'Failed to upload file');
        } finally {
            setUploading(false);
        }
    };

    const handleRemoveFile = () => {
        setFile(null);
        setPreview(null);
        onFileSelect(null);
        // Reset file input
        if (fileInputRef.current) {
            fileInputRef.current.value = "";
        }
    };

    return (
        <div className="my-4">
            {!file ? (
                <div
                    className={`border-2 border-dashed rounded-lg p-6 transition-colors ${isDragging
                        ? "border-indigo-500 bg-indigo-50"
                        : "border-gray-300 hover:border-indigo-400"
                        }`}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                >
                    <input
                        type="file"
                        onChange={handleFileChange}
                        accept=".pdf"
                        className="hidden"
                        id="file-upload"
                        ref={fileInputRef}
                    />
                    <label
                        htmlFor="file-upload"
                        className="flex flex-col items-center justify-center cursor-pointer"
                    >
                        <div className="p-3 rounded-full bg-indigo-100 mb-2">
                            <svg
                                className="w-10 h-10 text-indigo-500"
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
                        </div>
                        <p className="text-md font-medium text-gray-700">
                            Click to upload or drag and drop
                        </p>
                        <p className="mt-1 text-xs text-gray-500">PDF (max 10MB)</p>
                    </label>
                </div>
            ) : (
                <div className="bg-white rounded-lg border shadow-sm">
                    <div className="flex items-center justify-between border-b p-4">
                        <div className="flex items-center space-x-3">
                            <div className="p-2 bg-red-100 rounded-md">
                                <svg className="w-6 h-6 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                                </svg>
                            </div>
                            <div>
                                <p className="font-medium text-gray-700">{file.name}</p>
                                <p className="text-xs text-gray-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                            </div>
                        </div>
                        <button
                            onClick={handleRemoveFile}
                            className="p-1 rounded-full hover:bg-gray-100"
                            aria-label="Remove file"
                        >
                            <svg className="w-5 h-5 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>

                    {/* PDF Preview */}
                    <div className="p-4">
                        <div className="border rounded-md overflow-hidden bg-gray-100 h-250">
                            <iframe
                                src={preview}
                                title="PDF Preview"
                                className="w-full h-full"
                            />
                        </div>
                    </div>
                </div>
            )}

            {error && (
                <div className="mt-2 flex items-center text-red-600">
                    <svg className="w-4 h-4 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>{error}</span>
                </div>
            )}

            {success && !directUpload && (
                <div className="mt-2 flex items-center text-green-600">
                    <svg className="w-4 h-4 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                    </svg>
                    <span>File uploaded successfully!</span>
                </div>
            )}

            {file && projectId && !directUpload && (
                <div className="mt-4 flex justify-end">
                    <button
                        onClick={() => handleUpload()}
                        disabled={uploading}
                        className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:bg-indigo-300 disabled:cursor-not-allowed flex items-center space-x-2"
                    >
                        {uploading ? (
                            <>
                                <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                                <span>Uploading...</span>
                            </>
                        ) : (
                            <>
                                <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0l-4 4m4-4v12" />
                                </svg>
                                <span>Upload File</span>
                            </>
                        )}
                    </button>
                </div>
            )}
        </div>
    );
}