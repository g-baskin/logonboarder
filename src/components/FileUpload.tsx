'use client';

import { useCallback, useState } from 'react';
import { Upload, FileText, X } from 'lucide-react';

interface FileUploadProps {
  onFileRead: (content: string, filename: string) => void;
  acceptedTypes?: string[];
  maxSizeMB?: number;
}

export function FileUpload({
  onFileRead,
  acceptedTypes = ['.log', '.json', '.csv', '.txt', '.evtx'],
  maxSizeMB = 10,
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<{ name: string; size: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const validateFile = (file: File): string | null => {
    // Check file size
    const maxSizeBytes = maxSizeMB * 1024 * 1024;
    if (file.size > maxSizeBytes) {
      return `File size exceeds ${maxSizeMB}MB limit`;
    }

    // Check file extension
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!acceptedTypes.includes(ext)) {
      return `File type ${ext} not supported. Accepted types: ${acceptedTypes.join(', ')}`;
    }

    return null;
  };

  const readFile = useCallback(
    (file: File) => {
      const validationError = validateFile(file);
      if (validationError) {
        setError(validationError);
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        if (content) {
          onFileRead(content, file.name);
          setUploadedFile({ name: file.name, size: file.size });
          setError(null);
        }
      };
      reader.onerror = () => {
        setError('Failed to read file');
      };
      reader.readAsText(file);
    },
    [onFileRead, validateFile]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
        readFile(files[0]); // Only read first file for now
      }
    },
    [readFile]
  );

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      readFile(files[0]);
    }
  };

  const clearFile = () => {
    setUploadedFile(null);
    setError(null);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  return (
    <div className="w-full">
      {!uploadedFile ? (
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          className={`
            relative border-2 border-dashed rounded-lg p-8 text-center transition-colors
            ${isDragging ? 'border-blue-500 bg-blue-50 dark:bg-blue-950' : 'border-gray-300 dark:border-gray-700'}
            hover:border-gray-400 dark:hover:border-gray-600 cursor-pointer
          `}
        >
          <input
            type="file"
            id="file-upload"
            className="hidden"
            accept={acceptedTypes.join(',')}
            onChange={handleFileSelect}
          />
          <label htmlFor="file-upload" className="cursor-pointer">
            <Upload className="mx-auto h-12 w-12 text-gray-400" />
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              <span className="font-semibold text-blue-600 dark:text-blue-400">
                Click to upload
              </span>{' '}
              or drag and drop
            </p>
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-500">
              {acceptedTypes.join(', ')} (max {maxSizeMB}MB)
            </p>
          </label>
        </div>
      ) : (
        <div className="border border-gray-300 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-900">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileText className="h-8 w-8 text-blue-600 dark:text-blue-400" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                  {uploadedFile.name}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {formatFileSize(uploadedFile.size)}
                </p>
              </div>
            </div>
            <button
              onClick={clearFile}
              className="p-1 hover:bg-gray-200 dark:hover:bg-gray-800 rounded"
              title="Remove file"
            >
              <X className="h-5 w-5 text-gray-500" />
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-2 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950 p-2 rounded">
          {error}
        </div>
      )}
    </div>
  );
}
