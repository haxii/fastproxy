package plugin

import (
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/util"
	"github.com/haxii/log/v2"

	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type FileCache struct {
	basedir string

	fileCached     bool
	fileCachedPath string
	fileCachedFile *os.File

	fileDownloadPath     string
	fileDownloadFileSize int64
	fileDownloadFile     *os.File
}

func (c *FileCache) Init(basedir string, cacheKey string) {
	// init fields
	c.basedir = basedir

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
			log.Errorf(fileStoreFileErr, "cannot open cached file %s", c.fileCachedPath)
			if e := os.Remove(c.fileCachedPath); e != nil {
				log.Errorf(e, "cannot remove file %s", c.fileCachedPath)
			}
		} else {
			c.fileDownloadPath = ""
			c.fileDownloadFile = nil
			c.fileCached = true
			log.Debugf("file-cache %s, hit cache %s", cacheKey, c.fileCachedPath)
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
	if err = makeParentDir(c.fileDownloadPath); err != nil {
		log.Errorf(err, "file-cache cannot make parent dir of download path %s", c.fileDownloadPath)
		return
	}
	var fileDownloadFileCreateErr error
	c.fileDownloadFile, fileDownloadFileCreateErr = os.OpenFile(c.fileDownloadPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if fileDownloadFileCreateErr != nil {
		log.Errorf(fileDownloadFileCreateErr, "file-cache cannot create file %s", c.fileDownloadPath)
	}

	log.Debugf("file-cache %s, not in cache, downloading to %s", cacheKey, c.fileDownloadPath)
}

func (c *FileCache) FileCached() bool {
	return c.fileCached
}

var errUnexpectedStatusCode = errors.New("unexpected status code, expecting 200 or 3xx")

func (c *FileCache) WriteHeader(statusLine http.ResponseLine, header http.Header, rawHeader []byte) error {
	var err error
	c.fileDownloadFileSize, err = writeHeaderTo(c.fileDownloadFile, statusLine, header, rawHeader)
	return err
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
		log.Errorf(err, "file-cache fail to move downloaded file to cache %s", c.fileCachedPath)
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
			log.Errorf(err, "file-cache fail to remove downloaded tmp file %s", c.fileDownloadPath)
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

func writeHeaderTo(w io.Writer, statusLine http.ResponseLine,
	header http.Header, rawHeader []byte) (expectRespSize int64, err error) {
	if w == nil {
		return -1, errNothingToWrite
	}
	//do NOT save error to cache
	if code := statusLine.GetStatusCode(); !isRespCodeValid(code) {
		return -1, errUnexpectedStatusCode
	}
	if _, err := util.WriteWithValidation(w,
		statusLine.GetResponseLine()); err != nil {
		return -1, err
	}
	if _, err := util.WriteWithValidation(w, rawHeader); err != nil {
		return -1, err
	}
	expectRespSize = int64(len(statusLine.GetResponseLine()) + len(rawHeader))
	if header.ContentLength() > 0 {
		expectRespSize += header.ContentLength()
	} else {
		expectRespSize = -1
	}
	return expectRespSize, nil
}

func isRespCodeValid(code int) bool {
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
