import { useState, useRef, useEffect } from 'react';

const fileTypeConfig = {
    problem_statement: {
        title: 'Problem Statement',
        description: 'Upload the project problem statement (PDF only)',
        accept: '.pdf',
        mimeTypes: ['application/pdf'],
        maxSize: 10000, // 10000KB to match backend limit
        icon: (
            <svg className="w-8 h-8 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
        ),
        bgColor: 'bg-red-50',
        borderColor: 'border-red-200',
        iconBg: 'bg-red-100'
    },
    dataset: {
        title: 'Dataset',
        description: 'Upload project dataset (CSV, JSON, Excel, ZIP, etc.)',
        accept: '.csv,.json,.xls,.xlsx,.txt,.zip',
        mimeTypes: [
            'text/csv',
            'application/json',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain',
            'application/zip',
            'application/x-zip-compressed',
            'application/octet-stream' // For ZIP files detected as this type
        ],
        maxSize: 50 * 1024, // 50MB in KB (matches backend)
        icon: (
            <svg className="w-8 h-8 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
        ),
        bgColor: 'bg-blue-50',
        borderColor: 'border-blue-200',
        iconBg: 'bg-blue-100'
    },
    additional_resource: {
        title: 'Additional Resource',
        description: 'Upload any additional files (Documents, Images, etc.)',
        accept: '.pdf,.txt,.doc,.docx,.csv,.json,.xls,.xlsx,.zip,.jpg,.jpeg,.png,.gif',
        mimeTypes: [
            'application/pdf',
            'text/plain',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/csv',
            'application/json',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip',
            'application/x-zip-compressed',
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/octet-stream'
        ],
        maxSize: 20 * 1024, // 20MB in KB (matches backend)
        icon: (
            <svg className="w-8 h-8 text-green-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
            </svg>
        ),
        bgColor: 'bg-green-50',
        borderColor: 'border-green-200',
        iconBg: 'bg-green-100'
    }
};

interface FileUploadCardProps {
    fileType: 'problem_statement' | 'dataset' | 'additional_resource';
    onFileSelect: (fileType: string, file: File | null) => void;
    selectedFile: File | null;
    className?: string;
}

interface FileState {
    error: string | null;
    previewUrl: string | undefined;
    textContent: string | undefined;
    showPreview: boolean;
}

function FileUploadCard({ fileType, onFileSelect, selectedFile, className = '' }: FileUploadCardProps) {
    const [isDragging, setIsDragging] = useState(false);
    const [state, setState] = useState<FileState>({
        error: null,
        previewUrl: undefined,
        textContent: undefined,
        showPreview: false
    });
    const fileInputRef = useRef<HTMLInputElement>(null);

    const config = fileTypeConfig[fileType];

    // File type checks
    const isPDF = selectedFile?.type === 'application/pdf';
    const isImage = selectedFile?.type.startsWith('image/');

    useEffect(() => {
        if (selectedFile) {
            // Only create preview URL for images and PDFs
            if (isImage || isPDF) {
                const url = URL.createObjectURL(selectedFile);
                setState(prev => ({ ...prev, previewUrl: url }));
                return () => URL.revokeObjectURL(url);
            }
            // For text files, read content for preview
            else if (isTextFile(selectedFile) || isSpreadsheet(selectedFile)) {
                const reader = new FileReader();
                reader.onload = async (e) => {
                    try {
                        const result = e.target?.result;
                        if (result) {
                            setState(prev => ({ ...prev, textContent: result.toString() }));
                        }
                    } catch (error) {
                        console.error('Error reading file:', error);
                        setState(prev => ({ ...prev, error: 'Error reading file content' }));
                    }
                };

                reader.onerror = (error) => {
                    console.error('FileReader error:', error);
                    setState(prev => ({ ...prev, error: 'Error reading file' }));
                };

                reader.readAsText(selectedFile);
            }
        } else {
            setState(prev => ({ ...prev, previewUrl: undefined, textContent: undefined }));
        }
    }, [selectedFile, isImage, isPDF]);

    const isTextFile = (file: File): boolean => {
        const textTypes = ['text/plain', 'text/csv', 'text/javascript', 'text/html', 'text/css', 'application/json'];
        return textTypes.includes(file.type) || file.name.match(/\.(txt|csv|js|html|css|json|md)$/i) !== null;
    };

    const isSpreadsheet = (file: File): boolean => {
        const spreadsheetTypes = [
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/csv'
        ];
        return spreadsheetTypes.includes(file.type);
    };

    const validateFile = (file: File | null): string | null => {
        if (!file) return null;

        console.log(`Validating file for ${fileType}:`, {
            name: file.name,
            type: file.type,
            size: file.size
        });

        // Check file type - be more flexible with ZIP files
        let isValidType = false;

        if (config.mimeTypes.includes(file.type)) {
            isValidType = true;
        } else {
            // Special handling for ZIP files which can have different MIME types
            const fileName = file.name.toLowerCase();
            if (fileName.endsWith('.zip') &&
                (fileType === 'dataset' || fileType === 'additional_resource')) {
                isValidType = true;
            }
            // Special handling for CSV files
            else if (fileName.endsWith('.csv') && file.type === 'text/plain') {
                isValidType = true;
            }
        }

        if (!isValidType) {
            console.log(`File type validation failed. Expected: ${config.mimeTypes.join(', ')}, Got: ${file.type}`);
            return `Invalid file type. Allowed: ${config.accept}`;
        }

        // Check file size
        const fileSizeKB = file.size / 1024;
        if (fileSizeKB > config.maxSize) {
            const maxSizeDisplay = config.maxSize > 1024
                ? `${(config.maxSize / 1024).toFixed(0)}MB`
                : `${config.maxSize}KB`;
            console.log(`File size validation failed. Max: ${config.maxSize}KB, Got: ${fileSizeKB.toFixed(2)}KB`);
            return `File too large. Maximum size: ${maxSizeDisplay}`;
        }

        console.log(`File validation passed for ${fileType}`);
        return null;
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0] || null;
        if (file) {
            const validationError = validateFile(file);
            if (validationError) {
                setState(prev => ({ ...prev, error: validationError }));
                onFileSelect(fileType, null);
                return;
            }
        }
        processFile(file);
    };

    const processFile = (file: File | null) => {
        setState(prev => ({ ...prev, error: null }));

        if (!file) {
            onFileSelect(fileType, null);
            return;
        }

        const validationError = validateFile(file);

        if (validationError) {
            console.error(`Validation error for ${fileType}:`, validationError);
            setState(prev => ({ ...prev, error: validationError }));
            onFileSelect(fileType, null);
            return;
        }

        onFileSelect(fileType, file);
    };

    const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        setIsDragging(true);
    };

    const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
            setIsDragging(false);
        }
    };

    const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        setIsDragging(false);
        const file = e.dataTransfer.files[0] || null;
        if (file) {
            const validationError = validateFile(file);
            if (validationError) {
                setState(prev => ({ ...prev, error: validationError }));
                onFileSelect(fileType, null);
                return;
            }
        }
        processFile(file);
    };

    const handleRemoveFile = (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation(); // Stop event from reaching the parent container
        onFileSelect(fileType, null);
        setState(prev => ({
            ...prev,
            error: null,
            previewUrl: undefined,
            textContent: undefined,
            showPreview: false
        }));
        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }
    };

    const formatFileSize = (bytes: number): string => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const getMaxSizeDisplay = () => {
        return config.maxSize > 1024
            ? `${(config.maxSize / 1024).toFixed(0)}MB`
            : `${config.maxSize}KB`;
    };

    const isText = selectedFile && isTextFile(selectedFile);
    const isSheet = selectedFile && isSpreadsheet(selectedFile);
    const canPreview = isPDF || isImage || isText || isSheet;

    const parseCSV = (text: string): string[][] => {
        const lines = text.split('\n');
        return lines.map(line => line.split(',').map(cell => cell.trim()));
    };

    const formatTextContent = (content: string | undefined): JSX.Element => {
        if (!content) {
            return <div className="p-4 text-gray-500">No content to display</div>;
        }

        // Try to parse as CSV
        try {
            const data = parseCSV(content);
            return (
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            {data[0].map((header: string, i: number) => (
                                <th
                                    key={i}
                                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                                >
                                    {header}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {data.slice(1).map((row: string[], i: number) => (
                            <tr key={i}>
                                {row.map((cell: string, j: number) => (
                                    <td key={j} className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        {cell}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            );
        } catch {
            // If not CSV, display as plain text
            return (
                <pre className="whitespace-pre-wrap font-mono text-sm p-4">
                    {content}
                </pre>
            );
        }
    };

    const handlePreviewClick = (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setState(prev => ({ ...prev, showPreview: !prev.showPreview }));
    };

    return (
        <div className={`relative ${className}`}>
            <input
                ref={fileInputRef}
                type="file"
                accept={config.accept}
                onChange={handleFileChange}
                className="hidden"
            />
            <div className="flex flex-col space-y-4">
                {/* Upload Area */}
                <div
                    className={`border-2 border-dashed rounded-lg p-4 ${isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300'
                        } ${selectedFile ? 'bg-gray-50' : 'bg-white'}`}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                >
                    <div className="flex items-center justify-center">
                        <div className={`p-2 rounded-full ${config.iconBg}`}>
                            {config.icon}
                        </div>
                    </div>
                    <div className="mt-4 text-center">
                        <h3 className="text-gray-700 font-medium">{config.title}</h3>
                        <p className="text-sm text-gray-500 mt-1">{config.description}</p>
                    </div>
                    {selectedFile && (
                        <div className="mt-4 flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                                <span className="text-sm text-gray-500">{selectedFile.name}</span>
                                <span className="text-xs text-gray-400">({formatFileSize(selectedFile.size)})</span>
                            </div>
                            <div className="flex items-center space-x-2">
                                {(isPDF || isImage || isTextFile(selectedFile) || isSpreadsheet(selectedFile)) && (
                                    <button
                                        onClick={handlePreviewClick}
                                        className="px-3 py-1.5 text-sm bg-indigo-100 text-indigo-700 rounded hover:bg-indigo-200 transition-colors"
                                    >
                                        {state.showPreview ? 'Hide Preview' : 'Show Preview'}
                                    </button>
                                )}
                                <button
                                    onClick={handleRemoveFile}
                                    className="px-3 py-1.5 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors"
                                >
                                    Remove
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                {/* Preview Area */}
                {state.showPreview && selectedFile && (
                    <div className="border rounded-lg overflow-hidden bg-white">
                        <div className="p-4 bg-gray-50 border-b">
                            <h3 className="text-sm font-medium text-gray-700">File Preview</h3>
                        </div>
                        <div className="p-4" style={{ maxHeight: '1100px', overflowY: 'auto' }}>
                            {isPDF && state.previewUrl && (
                                <iframe
                                    src={state.previewUrl}
                                    className="w-full h-[1100px]"
                                    title="PDF preview"
                                />
                            )}
                            {isImage && state.previewUrl && (
                                <img
                                    src={state.previewUrl}
                                    alt="File preview"
                                    className="max-w-full max-h-[1100px] object-contain mx-auto"
                                />
                            )}
                            {(isTextFile(selectedFile) || isSpreadsheet(selectedFile)) && state.textContent && (
                                <div className="overflow-auto">
                                    {formatTextContent(state.textContent)}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>

            {state.error && (
                <div className="mt-2 flex items-center text-red-600">
                    <svg className="w-4 h-4 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="text-sm">{state.error}</span>
                </div>
            )}
        </div>
    );
}

interface MultiFileUploadProps {
    onFileSelect: (fileType: string, file: File | null) => void;
    files: {
        problem_statement: File | null;
        dataset: File | null;
        additional_resource: File | null;
    };
}

export default function MultiFileUpload({ onFileSelect, files }: MultiFileUploadProps) {
    console.log('MultiFileUpload rendered with files:', files);

    return (
        <div className="space-y-6">
            <FileUploadCard
                fileType="problem_statement"
                onFileSelect={onFileSelect}
                selectedFile={files.problem_statement}
            />

            <FileUploadCard
                fileType="dataset"
                onFileSelect={onFileSelect}
                selectedFile={files.dataset}
            />

            <FileUploadCard
                fileType="additional_resource"
                onFileSelect={onFileSelect}
                selectedFile={files.additional_resource}
            />
        </div>
    );
}