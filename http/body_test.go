package http

import (
	"testing"
)

func TestParseBodyField(t *testing.T) {
	testParseBodyFieldByBodyType(t, BodyTypeChunked)
	testParseBodyFieldByBodyType(t, BodyTypeFixedSize)
	testParseBodyFieldByBodyType(t, BodyTypeIdentity)
}

func testParseBodyFieldByBodyType(t *testing.T, btc BodyType) {

}
