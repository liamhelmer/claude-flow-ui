/**
 * File System Utilities Test Suite
 * Tests file operations, permissions, and security validations
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  createDirectory,
  ensureDirectoryExists,
  validateFilePath,
  sanitizeFileName,
  checkFilePermissions,
  safeReadFile,
  safeWriteFile,
  calculateDirectorySize,
  cleanupTempFiles,
  watchFileChanges,
  compressFile,
  extractArchive,
  syncDirectories,
  validateFileType,
  quarantineFile
} = require('../file-system-utils');

// Mock fs operations
jest.mock('fs', () => ({
  existsSync: jest.fn(),
  mkdirSync: jest.fn(),
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
  unlinkSync: jest.fn(),
  readdirSync: jest.fn(),
  statSync: jest.fn(),
  lstatSync: jest.fn(() => ({ isSymbolicLink: () => false })),
  accessSync: jest.fn(),
  constants: {
    F_OK: 0,
    R_OK: 4,
    W_OK: 2,
    X_OK: 1
  },
  promises: {
    access: jest.fn(),
    readFile: jest.fn(),
    writeFile: jest.fn(),
    readdir: jest.fn(),
    stat: jest.fn(() => Promise.resolve({ size: 100 })),
    mkdir: jest.fn(),
    unlink: jest.fn(),
    rename: jest.fn()
  },
  watch: jest.fn(),
  createReadStream: jest.fn(),
  createWriteStream: jest.fn()
}));

jest.mock('path');
jest.mock('os');

describe('File System Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.mocked(path.join).mockImplementation((...args) => args.join('/'));
    jest.mocked(path.resolve).mockImplementation((p) => `/resolved/${p}`);
    jest.mocked(path.dirname).mockImplementation((p) => p.split('/').slice(0, -1).join('/') || '/');
    jest.mocked(path.basename).mockImplementation((p) => p.split('/').pop() || '');
    jest.mocked(path.extname).mockImplementation((p) => {
      const name = p.split('/').pop() || '';
      const dotIndex = name.lastIndexOf('.');
      return dotIndex > 0 ? name.substring(dotIndex) : '';
    });
    jest.mocked(os.tmpdir).mockReturnValue('/tmp');
  });

  describe('createDirectory', () => {
    it('should create directory with proper permissions', () => {
      jest.mocked(fs.existsSync).mockReturnValue(false);
      
      createDirectory('/test/dir', 0o755);
      
      expect(fs.mkdirSync).toHaveBeenCalledWith('/test/dir', {
        recursive: true,
        mode: 0o755
      });
    });

    it('should not create directory if it already exists', () => {
      jest.mocked(fs.existsSync).mockReturnValue(true);
      
      createDirectory('/existing/dir');
      
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });

    it('should handle permission errors', () => {
      jest.mocked(fs.existsSync).mockReturnValue(false);
      jest.mocked(fs.mkdirSync).mockImplementation(() => {
        throw new Error('EACCES: permission denied');
      });
      
      expect(() => createDirectory('/restricted/dir')).toThrow('permission denied');
    });

    it('should create nested directories', () => {
      jest.mocked(fs.existsSync).mockReturnValue(false);
      
      createDirectory('/deep/nested/directory/structure');
      
      expect(fs.mkdirSync).toHaveBeenCalledWith('/deep/nested/directory/structure', {
        recursive: true,
        mode: 0o755
      });
    });
  });

  describe('ensureDirectoryExists', () => {
    it('should ensure directory exists and create if needed', async () => {
      const error = new Error('ENOENT');
      error.code = 'ENOENT';
      jest.mocked(fs.promises.access).mockRejectedValue(error);
      jest.mocked(fs.promises.mkdir).mockResolvedValue(undefined);
      
      await ensureDirectoryExists('/test/dir');
      
      expect(fs.promises.access).toHaveBeenCalledWith('/test/dir');
      expect(fs.promises.mkdir).toHaveBeenCalledWith('/test/dir', { recursive: true });
    });

    it('should not create directory if it already exists', async () => {
      jest.mocked(fs.promises.access).mockResolvedValue(undefined);
      
      await ensureDirectoryExists('/existing/dir');
      
      expect(fs.promises.mkdir).not.toHaveBeenCalled();
    });

    it('should handle async creation errors', async () => {
      const accessError = new Error('ENOENT');
      accessError.code = 'ENOENT';
      const mkdirError = new Error('EACCES');
      mkdirError.code = 'EACCES';
      jest.mocked(fs.promises.access).mockRejectedValue(accessError);
      jest.mocked(fs.promises.mkdir).mockRejectedValue(mkdirError);
      
      await expect(ensureDirectoryExists('/restricted/dir'))
        .rejects.toThrow('EACCES');
    });
  });

  describe('validateFilePath', () => {
    it('should validate safe file paths', () => {
      const safePaths = [
        'documents/file.txt',
        'projects/app/src/index.js',
        'images/photo.jpg'
      ];

      safePaths.forEach(path => {
        expect(validateFilePath(path)).toBe(true);
      });
    });

    it('should reject dangerous file paths', () => {
      const dangerousPaths = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32',
        '/etc/passwd',
        'C:\\Windows\\System32',
        '../../../../root/.ssh/id_rsa'
      ];

      dangerousPaths.forEach(path => {
        expect(validateFilePath(path)).toBe(false);
      });
    });

    it('should reject null-byte injection attempts', () => {
      const nullBytePaths = [
        'file.txt\\x00.exe',
        'document.pdf\\0shell.sh',
        'image.jpg\\x00; rm -rf /'
      ];

      nullBytePaths.forEach(path => {
        expect(validateFilePath(path)).toBe(false);
      });
    });

    it('should validate path length limits', () => {
      const longPath = 'a/'.repeat(1000) + 'file.txt';
      expect(validateFilePath(longPath)).toBe(false);
    });

    it('should handle empty and invalid paths', () => {
      expect(validateFilePath('')).toBe(false);
      expect(validateFilePath(null)).toBe(false);
      expect(validateFilePath(undefined)).toBe(false);
    });
  });

  describe('sanitizeFileName', () => {
    it('should remove unsafe characters from filename', () => {
      const unsafeNames = [
        'file<name>.txt',
        'document|with|pipes.pdf',
        'image"with"quotes.jpg',
        'script:with:colons.js'
      ];

      unsafeNames.forEach(name => {
        const sanitized = sanitizeFileName(name);
        expect(sanitized).not.toMatch(/[<>|":*?]/);
        expect(sanitized.length).toBeGreaterThan(0);
      });
    });

    it('should handle reserved Windows names', () => {
      const reservedNames = [
        'CON.txt',
        'PRN.log',
        'AUX.data',
        'NUL.file',
        'COM1.txt',
        'LPT1.doc'
      ];

      reservedNames.forEach(name => {
        const sanitized = sanitizeFileName(name);
        expect(sanitized).not.toBe(name);
        expect(sanitized).toMatch(/^_/); // Should prefix with underscore
      });
    });

    it('should preserve file extensions', () => {
      const filename = 'my<unsafe>file.txt';
      const sanitized = sanitizeFileName(filename);
      
      expect(sanitized).toMatch(/\.txt$/);
      expect(sanitized).not.toContain('<');
      expect(sanitized).not.toContain('>');
    });

    it('should handle very long filenames', () => {
      const longName = 'a'.repeat(300) + '.txt';
      const sanitized = sanitizeFileName(longName);
      
      expect(sanitized.length).toBeLessThan(256);
      expect(sanitized).toMatch(/\.txt$/);
    });

    it('should handle unicode characters appropriately', () => {
      const unicodeName = '测试文件名🚀.txt';
      const sanitized = sanitizeFileName(unicodeName);
      
      expect(sanitized).toContain('测试文件名');
      expect(sanitized).toContain('🚀');
      expect(sanitized).toMatch(/\.txt$/);
    });
  });

  describe('checkFilePermissions', () => {
    it('should check read permissions', () => {
      jest.mocked(fs.accessSync).mockImplementation(() => undefined);
      
      const hasRead = checkFilePermissions('/test/file.txt', 'read');
      
      expect(hasRead).toBe(true);
      expect(fs.accessSync).toHaveBeenCalledWith('/test/file.txt', fs.constants.R_OK);
    });

    it('should check write permissions', () => {
      jest.mocked(fs.accessSync).mockImplementation(() => undefined);
      
      const hasWrite = checkFilePermissions('/test/file.txt', 'write');
      
      expect(hasWrite).toBe(true);
      expect(fs.accessSync).toHaveBeenCalledWith('/test/file.txt', fs.constants.W_OK);
    });

    it('should check execute permissions', () => {
      jest.mocked(fs.accessSync).mockImplementation(() => undefined);
      
      const hasExecute = checkFilePermissions('/test/script.sh', 'execute');
      
      expect(hasExecute).toBe(true);
      expect(fs.accessSync).toHaveBeenCalledWith('/test/script.sh', fs.constants.X_OK);
    });

    it('should return false for insufficient permissions', () => {
      jest.mocked(fs.accessSync).mockImplementation(() => {
        throw new Error('EACCES: permission denied');
      });
      
      const hasPermission = checkFilePermissions('/restricted/file.txt', 'read');
      
      expect(hasPermission).toBe(false);
    });

    it('should handle non-existent files', () => {
      jest.mocked(fs.accessSync).mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory');
      });
      
      const hasPermission = checkFilePermissions('/nonexistent/file.txt', 'read');
      
      expect(hasPermission).toBe(false);
    });
  });

  describe('safeReadFile', () => {
    it('should read file safely with size limits', async () => {
      const fileContent = 'Hello, world!';
      jest.mocked(fs.promises.stat).mockResolvedValue({ size: fileContent.length });
      jest.mocked(fs.promises.readFile).mockResolvedValue(Buffer.from(fileContent));
      
      const content = await safeReadFile('/test/file.txt', { maxSize: 1000 });
      
      expect(content).toBe(fileContent);
      expect(fs.promises.stat).toHaveBeenCalledWith('/test/file.txt');
    });

    it('should reject files that are too large', async () => {
      jest.mocked(fs.promises.stat).mockResolvedValue({ size: 2000000 });
      
      await expect(safeReadFile('/huge/file.txt', { maxSize: 1000000 }))
        .rejects.toThrow('File size exceeds maximum allowed');
    });

    it('should validate file type before reading', async () => {
      jest.mocked(fs.promises.stat).mockResolvedValue({ size: 100 });
      
      await expect(safeReadFile('/test/malicious.exe', { 
        allowedExtensions: ['.txt', '.json', '.md'] 
      })).rejects.toThrow('File type not allowed');
    });

    it('should handle read errors gracefully', async () => {
      jest.mocked(fs.promises.stat).mockResolvedValue({ size: 100 });
      jest.mocked(fs.promises.readFile).mockRejectedValue(new Error('EACCES'));
      
      await expect(safeReadFile('/restricted/file.txt'))
        .rejects.toThrow('EACCES');
    });

    it('should support different encodings', async () => {
      const content = 'UTF-8 content with émojis 🚀';
      jest.mocked(fs.promises.stat).mockResolvedValue({ size: content.length });
      jest.mocked(fs.promises.readFile).mockResolvedValue(content);
      
      const result = await safeReadFile('/test/utf8.txt', { encoding: 'utf8' });
      
      expect(result).toBe(content);
      expect(fs.promises.readFile).toHaveBeenCalledWith('/test/utf8.txt', { encoding: 'utf8' });
    });
  });

  describe('safeWriteFile', () => {
    it('should write file safely with backup', async () => {
      jest.mocked(fs.existsSync).mockReturnValue(true);
      jest.mocked(fs.promises.readFile).mockResolvedValue(Buffer.from('old content'));
      jest.mocked(fs.promises.writeFile).mockResolvedValue(undefined);
      
      await safeWriteFile('/test/file.txt', 'new content', { createBackup: true });
      
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        expect.stringContaining('file.txt.backup'),
        Buffer.from('old content')
      );
      expect(fs.promises.writeFile).toHaveBeenCalledWith('/test/file.txt', 'new content');
    });

    it('should respect file size limits', async () => {
      const largeContent = 'x'.repeat(2000000);
      
      await expect(safeWriteFile('/test/large.txt', largeContent, { maxSize: 1000000 }))
        .rejects.toThrow('Content size exceeds maximum allowed');
    });

    it('should validate directory permissions before writing', async () => {
      jest.mocked(fs.promises.access).mockRejectedValue(new Error('EACCES'));
      
      await expect(safeWriteFile('/restricted/dir/file.txt', 'content'))
        .rejects.toThrow('Directory not writable');
    });

    it('should create atomic writes with temp files', async () => {
      const mockTempFile = '/tmp/temp-file-123';
      jest.mocked(fs.promises.writeFile).mockResolvedValue(undefined);
      
      await safeWriteFile('/test/important.txt', 'critical data', { atomic: true });
      
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        expect.stringContaining('.tmp'),
        'critical data'
      );
    });

    it('should handle write permission errors', async () => {
      jest.mocked(fs.promises.writeFile).mockRejectedValue(new Error('EACCES'));
      
      await expect(safeWriteFile('/readonly/file.txt', 'content'))
        .rejects.toThrow('EACCES');
    });
  });

  describe('calculateDirectorySize', () => {
    it('should calculate total directory size', async () => {
      const mockFiles = [
        { name: 'file1.txt', isDirectory: () => false, size: 1000 },
        { name: 'file2.jpg', isDirectory: () => false, size: 2000 },
        { name: 'subdir', isDirectory: () => true }
      ];

      jest.mocked(fs.promises.readdir).mockResolvedValue(mockFiles);
      jest.mocked(fs.promises.stat).mockImplementation((filePath) => {
        if (filePath.toString().includes('subdir')) {
          return Promise.resolve({ isDirectory: () => true, size: 0 });
        }
        const fileName = filePath.toString().split('/').pop();
        const file = mockFiles.find(f => f.name === fileName);
        return Promise.resolve({ 
          isDirectory: () => false, 
          size: file?.size || 0 
        } );
      });

      // Mock recursive call for subdirectory
      jest.mocked(fs.promises.readdir).mockResolvedValueOnce([
        { name: 'nested.txt', isDirectory: () => false, size: 500 }
      ] );

      const totalSize = await calculateDirectorySize('/test/directory');
      
      expect(totalSize).toBe(3500); // 1000 + 2000 + 500
    });

    it('should handle empty directories', async () => {
      jest.mocked(fs.promises.readdir).mockResolvedValue([]);
      
      const size = await calculateDirectorySize('/empty/dir');
      
      expect(size).toBe(0);
    });

    it('should handle permission errors on subdirectories', async () => {
      jest.mocked(fs.promises.readdir).mockRejectedValueOnce(new Error('EACCES'));
      
      const size = await calculateDirectorySize('/restricted/dir', { ignoreErrors: true });
      
      expect(size).toBe(0);
    });

    it('should respect maximum depth limits', async () => {
      const mockDeepStructure = [
        { name: 'level1', isDirectory: () => true }
      ];

      jest.mocked(fs.promises.readdir).mockResolvedValue(mockDeepStructure );
      jest.mocked(fs.promises.stat).mockResolvedValue({ 
        isDirectory: () => true 
      } );

      const size = await calculateDirectorySize('/deep/structure', { maxDepth: 1 });
      
      expect(size).toBe(0); // Should not recurse beyond maxDepth
    });
  });

  describe('cleanupTempFiles', () => {
    beforeEach(() => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2025-01-01 12:00:00'));
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should clean up old temporary files', async () => {
      const oldTime = new Date('2025-01-01 10:00:00'); // 2 hours ago
      const recentTime = new Date('2025-01-01 11:30:00'); // 30 minutes ago

      const mockFiles = [
        'temp-old-file-123.tmp',
        'temp-recent-file-456.tmp',
        'not-temp-file.txt'
      ];

      jest.mocked(fs.promises.readdir).mockResolvedValue(mockFiles);
      jest.mocked(fs.promises.stat).mockImplementation((filePath) => {
        if (filePath.toString().includes('old')) {
          return Promise.resolve({ mtime: oldTime } );
        }
        return Promise.resolve({ mtime: recentTime } );
      });
      jest.mocked(fs.promises.unlink).mockResolvedValue(undefined);

      await cleanupTempFiles('/tmp', { maxAge: 3600000 }); // 1 hour

      expect(fs.promises.unlink).toHaveBeenCalledWith('/tmp/temp-old-file-123.tmp');
      expect(fs.promises.unlink).not.toHaveBeenCalledWith('/tmp/temp-recent-file-456.tmp');
      expect(fs.promises.unlink).not.toHaveBeenCalledWith('/tmp/not-temp-file.txt');
    });

    it('should respect file pattern filters', async () => {
      const mockFiles = [
        'app-temp-123.tmp',
        'other-temp-456.tmp',
        'app-cache-789.cache'
      ];

      jest.mocked(fs.promises.readdir).mockResolvedValue(mockFiles);
      jest.mocked(fs.promises.stat).mockResolvedValue({ 
        mtime: new Date('2025-01-01 08:00:00') 
      } );

      await cleanupTempFiles('/tmp', { 
        pattern: /^app-.*\.(tmp|cache)$/,
        maxAge: 0
      });

      expect(fs.promises.unlink).toHaveBeenCalledWith('/tmp/app-temp-123.tmp');
      expect(fs.promises.unlink).toHaveBeenCalledWith('/tmp/app-cache-789.cache');
      expect(fs.promises.unlink).not.toHaveBeenCalledWith('/tmp/other-temp-456.tmp');
    });

    it('should handle cleanup errors gracefully', async () => {
      const mockFiles = ['problematic-file.tmp'];
      
      jest.mocked(fs.promises.readdir).mockResolvedValue(mockFiles);
      jest.mocked(fs.promises.stat).mockResolvedValue({ 
        mtime: new Date('2025-01-01 08:00:00') 
      } );
      jest.mocked(fs.promises.unlink).mockRejectedValue(new Error('EACCES'));

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      await cleanupTempFiles('/tmp', { maxAge: 0, ignoreErrors: true });

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to delete'),
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });
  });

  describe('watchFileChanges', () => {
    let mockWatcher;

    beforeEach(() => {
      mockWatcher = {
        on: jest.fn(),
        close: jest.fn()
      };
      jest.mocked(fs.watch).mockReturnValue(mockWatcher);
    });

    it('should watch file changes', () => {
      const onChange = jest.fn();
      
      const watcher = watchFileChanges('/test/file.txt', onChange);
      
      expect(fs.watch).toHaveBeenCalledWith('/test/file.txt', expect.any(Object));
      expect(mockWatcher.on).toHaveBeenCalledWith('change', expect.any(Function));
      expect(watcher).toBe(mockWatcher);
    });

    it('should handle file change events', () => {
      const onChange = jest.fn();
      
      watchFileChanges('/test/file.txt', onChange);
      
      // Simulate file change
      const changeCallback = mockWatcher.on.mock.calls.find(call => call[0] === 'change')[1];
      changeCallback('change', 'file.txt');
      
      expect(onChange).toHaveBeenCalledWith('change', '/test/file.txt');
    });

    it('should handle watcher errors', () => {
      const onError = jest.fn();
      
      watchFileChanges('/test/file.txt', jest.fn(), { onError });
      
      // Simulate error
      const errorCallback = mockWatcher.on.mock.calls.find(call => call[0] === 'error')[1];
      const testError = new Error('ENOENT');
      errorCallback(testError);
      
      expect(onError).toHaveBeenCalledWith(testError);
    });

    it('should support recursive directory watching', () => {
      watchFileChanges('/test/directory', jest.fn(), { recursive: true });
      
      expect(fs.watch).toHaveBeenCalledWith('/test/directory', {
        recursive: true,
        persistent: true
      });
    });
  });

  describe('validateFileType', () => {
    it('should validate file types by extension', () => {
      expect(validateFileType('document.pdf', ['.pdf', '.doc'])).toBe(true);
      expect(validateFileType('image.jpg', ['.png', '.gif'])).toBe(false);
    });

    it('should validate file types by MIME type', () => {
      // Mock file reading for MIME detection
      jest.mocked(fs.readFileSync).mockReturnValue(Buffer.from([0x25, 0x50, 0x44, 0x46])); // PDF magic bytes
      
      expect(validateFileType('file.pdf', [], ['application/pdf'])).toBe(true);
    });

    it('should handle case-insensitive extensions', () => {
      expect(validateFileType('IMAGE.JPG', ['.jpg', '.png'])).toBe(true);
      expect(validateFileType('document.PDF', ['.pdf'])).toBe(true);
    });

    it('should reject files with no extension when required', () => {
      expect(validateFileType('noextension', ['.txt', '.md'])).toBe(false);
    });

    it('should validate against dangerous file types', () => {
      const dangerousTypes = ['.exe', '.bat', '.cmd', '.scr', '.com'];
      
      dangerousTypes.forEach(ext => {
        expect(validateFileType(`malware${ext}`, ['.txt'])).toBe(false);
      });
    });
  });

  describe('Security and Edge Cases', () => {
    it('should handle symbolic link attacks', async () => {
      jest.mocked(fs.lstatSync).mockReturnValue({ 
        isSymbolicLink: () => true 
      } );
      
      expect(() => validateFilePath('/test/symlink.txt', { followSymlinks: false }))
        .toThrow('Symbolic links not allowed');
    });

    it('should prevent directory traversal in archives', async () => {
      const maliciousEntry = '../../../etc/passwd';
      
      expect(() => validateFilePath(maliciousEntry))
        .not.toThrow(); // Should be caught by validateFilePath

      expect(validateFilePath(maliciousEntry)).toBe(false);
    });

    it('should handle race conditions in file operations', async () => {
      let callCount = 0;
      jest.mocked(fs.promises.writeFile).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          throw new Error('EEXIST: file exists');
        }
        return Promise.resolve();
      });

      await expect(safeWriteFile('/test/file.txt', 'content', { retryOnRace: true }))
        .resolves.toBeUndefined();

      expect(fs.promises.writeFile).toHaveBeenCalledTimes(2);
    });

    it('should handle disk space checks', async () => {
      // Mock statvfs or similar system call
      const mockDiskInfo = {
        free: 1000000,
        size: 10000000
      };

      const largeContent = 'x'.repeat(2000000);

      await expect(safeWriteFile('/test/large.txt', largeContent, { 
        checkDiskSpace: true,
        minFreeSpace: 5000000 
      })).rejects.toThrow('Insufficient disk space');
    });

    it('should handle concurrent file access', async () => {
      let lockAcquired = false;
      
      const mockLock = {
        acquire: jest.fn(() => {
          if (lockAcquired) throw new Error('EBUSY');
          lockAcquired = true;
          return Promise.resolve();
        }),
        release: jest.fn(() => {
          lockAcquired = false;
          return Promise.resolve();
        })
      };

      await expect(safeWriteFile('/test/shared.txt', 'content', { 
        useLocking: true,
        lock: mockLock 
      })).resolves.toBeUndefined();

      expect(mockLock.acquire).toHaveBeenCalled();
      expect(mockLock.release).toHaveBeenCalled();
    });

    it('should handle file system limits', async () => {
      const manyFiles = Array.from({ length: 10000 }, (_, i) => `file${i}.txt`);
      
      jest.mocked(fs.promises.readdir).mockResolvedValue(manyFiles);

      await expect(calculateDirectorySize('/huge/directory', { 
        maxFiles: 5000 
      })).rejects.toThrow('Directory contains too many files');
    });
  });

  describe('Performance and Memory', () => {
    it('should handle large files efficiently', async () => {
      const mockReadStream = {
        on: jest.fn(),
        pipe: jest.fn(),
        destroy: jest.fn()
      };

      jest.mocked(fs.createReadStream).mockReturnValue(mockReadStream );

      const content = await safeReadFile('/huge/file.txt', { 
        useStreaming: true,
        maxSize: 1000000000 
      });

      expect(fs.createReadStream).toHaveBeenCalledWith('/huge/file.txt');
    });

    it('should implement proper cleanup on errors', async () => {
      const mockTempFile = '/tmp/temp-123';
      
      jest.mocked(fs.promises.writeFile).mockRejectedValue(new Error('ENOSPC'));

      await expect(safeWriteFile('/test/file.txt', 'content', { 
        atomic: true,
        tempFile: mockTempFile 
      })).rejects.toThrow('ENOSPC');

      // Should attempt cleanup of temp file
      expect(fs.promises.unlink).toHaveBeenCalledWith(mockTempFile);
    });

    it('should throttle file operations', async () => {
      const operations = Array.from({ length: 100 }, (_, i) => 
        safeReadFile(`/test/file${i}.txt`, { 
          throttle: true,
          maxConcurrent: 10 
        })
      );

      // Should not overwhelm the system
      await Promise.all(operations);

      expect(fs.promises.readFile).toHaveBeenCalledTimes(100);
    });
  });
});