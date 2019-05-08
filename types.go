package main

type Action int

const (
  Unset Action = iota
  Encrypt Action = iota
  Decrypt Action = iota
)

type Options struct {
  operation Action
  sourceFile string
  outputFile string
  password []byte
}
