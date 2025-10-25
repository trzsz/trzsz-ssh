/*
MIT License

Copyright (c) 2021-2025 Charmbracelet, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package table

import (
	"sort"
)

// btoi converts a boolean to an integer, 1 if true, 0 if false.
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// max returns the greater of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the greater of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sum returns the sum of all integers in a slice.
func sum(n []int) int {
	var sum int
	for _, i := range n {
		sum += i
	}
	return sum
}

// median returns the median of a slice of integers.
func median(n []int) int {
	sort.Ints(n)

	if len(n) <= 0 {
		return 0
	}
	if len(n)%2 == 0 {
		h := len(n) / 2            //nolint:gomnd
		return (n[h-1] + n[h]) / 2 //nolint:gomnd
	}
	return n[len(n)/2]
}

// largest returns the largest element and it's index from a slice of integers.
func largest(n []int) (int, int) { //nolint:unparam
	var largest, index int
	for i, e := range n {
		if n[i] > n[index] {
			largest = e
			index = i
		}
	}
	return index, largest
}
