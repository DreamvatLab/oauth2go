package server

import (
	"net/http"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/valyala/fasthttp"
)

const (
	_get    = "GET"
	_post   = "POST"
	_put    = "PUT"
	_delete = "DELETE"
)

func NewWebServer() IWebServer {
	return &defaultRouter{
		routingTable: make(map[string]map[string]fasthttp.RequestHandler),
	}
}

type defaultRouter struct {
	routingTable map[string]map[string]fasthttp.RequestHandler
	fileHandler  fasthttp.RequestHandler
}

func (x *defaultRouter) Get(path string, handler fasthttp.RequestHandler) {
	x.addSubRoutes(path, _get, handler)
}
func (x *defaultRouter) Post(path string, handler fasthttp.RequestHandler) {
	x.addSubRoutes(path, _post, handler)
}
func (x *defaultRouter) Put(path string, handler fasthttp.RequestHandler) {
	x.addSubRoutes(path, _put, handler)
}
func (x *defaultRouter) Delete(path string, handler fasthttp.RequestHandler) {
	x.addSubRoutes(path, _delete, handler)
}

func (x *defaultRouter) addSubRoutes(path, method string, handler fasthttp.RequestHandler) {
	if route := x.routingTable[path]; route != nil {
		route[method] = handler
	} else {
		x.routingTable[path] = make(map[string]fasthttp.RequestHandler)
		x.routingTable[path][method] = handler
	}
}

func (x *defaultRouter) ServeFiles(handler fasthttp.RequestHandler) {
	x.fileHandler = handler
}

func (x *defaultRouter) Serve(ctx *fasthttp.RequestCtx) {
	path := xbytes.BytesToStr(ctx.URI().Path()) // Todo: use pool
	if pathRoute, ok := x.routingTable[path]; ok {
		method := xbytes.BytesToStr(ctx.Method()) // Todo: use pool
		if handler, ok := pathRoute[method]; ok {
			handler(ctx)
		}
	} else if x.fileHandler != nil {
		x.fileHandler(ctx)
	} else {
		ctx.SetStatusCode(http.StatusNotFound)
	}
}
