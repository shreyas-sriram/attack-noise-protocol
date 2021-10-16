run: build
	@./compromiser

build:
	@go build .

clean:
	@rm client-* server-* compromiser
