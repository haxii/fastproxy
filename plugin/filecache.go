package plugin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/util"
	"github.com/haxii/log"
)

type FileCache struct {
	basedir string
	logger  log.Logger

	fileCached     bool
	fileCachedPath string
	fileCachedFile *os.File

	fileDownloadPath     string
	fileDownloadFileSize int64
	fileDownloadFile     *os.File
}

func (c *FileCache) Init(basedir string, logger log.Logger, cacheKey string) {
	// init fields
	c.basedir = basedir
	c.logger = logger

	// reset fields
	c.fileCached = false
	c.fileCachedPath = ""
	c.fileCachedFile = nil
	c.fileDownloadPath = ""
	c.fileDownloadFileSize = -1
	c.fileDownloadFile = nil

	// check if the file has been cached
	c.fileCachedPath = filepath.Join(c.basedir, "cache", cacheKey)
	if exist, _ := exists(c.fileCachedPath); exist {
		var fileStoreFileErr error
		c.fileCachedFile, fileStoreFileErr = os.Open(c.fileCachedPath)
		if fileStoreFileErr != nil {
			c.logger.Error("FileCache",
				fileStoreFileErr, "cannot open cached file %s", c.fileCachedPath)
			if e := os.Remove(c.fileCachedPath); e != nil {
				c.logger.Error("FileCache",
					e, "cannot remove file %s", c.fileCachedPath)
			}
		} else {
			c.fileDownloadPath = ""
			c.fileDownloadFile = nil
			c.fileCached = true
			c.logger.Debug("FileCache", "%s, hit cache %s", cacheKey, c.fileCachedPath)
			return
		}
	}

	// make download tmp file if not cached
	downloadingKey := make([]byte, 16)
	_, err := rand.Read(downloadingKey)
	if err != nil {
		return
	}
	c.fileDownloadPath = filepath.Join(c.basedir, "downloading", hex.EncodeToString(downloadingKey))
	if err := makeParentDir(c.fileDownloadPath); err != nil {
		c.logger.Error("FileCache",
			err, "cannot make parent dir of download path %s", c.fileDownloadPath)
		return
	}
	var fileDownloadFileCreateErr error
	c.fileDownloadFile, fileDownloadFileCreateErr = os.OpenFile(c.fileDownloadPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if fileDownloadFileCreateErr != nil {
		c.logger.Error("FileCache", fileDownloadFileCreateErr,
			"cannot create file %s", c.fileDownloadPath)
	}

	c.logger.Info("FileCache", "%s, not in cache, downloading to %s", cacheKey, c.fileDownloadPath)
}

func (c *FileCache) FileCached() bool {
	return c.fileCached
}

var errUnexpectedStatusCode = errors.New("unexpected status code, expecting 200 or 3xx")

func (c *FileCache) WriteHeader(statusLine http.ResponseLine, header http.Header, rawHeader []byte) error {
	if c.fileDownloadFile == nil {
		return errNothingToWrite
	}
	//do NOT save error to cache
	if code := statusLine.GetStatusCode(); !c.isRespCodeValid(code) {
		return errUnexpectedStatusCode
	}
	if _, err := util.WriteWithValidation(c.fileDownloadFile,
		statusLine.GetResponseLine()); err != nil {
		return err
	}
	if _, err := util.WriteWithValidation(c.fileDownloadFile, rawHeader); err != nil {
		return err
	}
	c.fileDownloadFileSize = int64(len(statusLine.GetResponseLine()) + len(rawHeader))
	if header.ContentLength() > 0 {
		c.fileDownloadFileSize += header.ContentLength()
	} else {
		c.fileDownloadFileSize = 0
	}
	return nil
}

var errNothingToWrite = errors.New("noting to write")

func (c *FileCache) Write(p []byte) (n int, err error) {
	if c.fileDownloadFile == nil {
		return 0, errNothingToWrite
	}
	return c.fileDownloadFile.Write(p)
}

var errNothingToRead = errors.New("noting to read")

func (c *FileCache) Read(b []byte) (n int, err error) {
	if c.fileCachedFile == nil {
		return 0, errNothingToRead
	}
	return c.fileCachedFile.Read(b)
}

func (c *FileCache) Close() error {
	// move the downloaded file to cache destination
	if err := c.moveDownloadedFileToCache(); err != nil {
		c.logger.Error("FileCache", err,
			"fail to move downloaded file to cache %s", c.fileCachedPath)
	}
	// close file
	var errClose error
	if c.fileDownloadFile != nil {
		errClose = c.fileDownloadFile.Close()
	}
	if c.fileCachedFile != nil {
		if err := c.fileCachedFile.Close(); err != nil {
			errClose = err
		}
	}
	// delete unnamed cached file
	if exist, _ := exists(c.fileDownloadPath); exist {
		if err := os.Remove(c.fileDownloadPath); err != nil {
			c.logger.Error("FileCache", err,
				"fail to remove downloaded tmp file %s", c.fileDownloadPath)
		}
	}
	return errClose
}

func (c *FileCache) moveDownloadedFileToCache() error {
	if !c.fileCached && c.fileDownloadFile != nil {
		if err := c.checkDownloadedFile(); err != nil {
			return err
		}
		//move downloaded file to cache folder
		if err := makeParentDir(c.fileCachedPath); err != nil {
			return err
		}
		return os.Rename(c.fileDownloadPath, c.fileCachedPath)
	}
	return nil
}

var errIncompleteDownload = errors.New("incomplete download")

func (c *FileCache) checkDownloadedFile() error {
	stat, err := c.fileDownloadFile.Stat()
	if err != nil {
		return err
	}
	if stat.Size() < 1 {
		return errIncompleteDownload
	}
	if c.fileDownloadFileSize > 0 &&
		c.fileDownloadFileSize != stat.Size() {
		return errIncompleteDownload
	}
	return nil
}

func (c *FileCache) isRespCodeValid(code int) bool {
	if code == 200 {
		return true
	}
	if code < 400 && code > 300 {
		if code == 304 {
			return false
		}
		return true
	}
	return false
}

// exists Check if a file or directory exists.
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func makeParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0755)
}
