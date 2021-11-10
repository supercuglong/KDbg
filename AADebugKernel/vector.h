// The MIT License (MIT)
// Copyright (c) 2016 Peter Goldsborough
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef VECTOR_H
#define VECTOR_H

#include <ntifs.h>

#define memory_targe 'dbg'

void* __malloc(ULONG _size);

void __free(void* _ptr);


/***** DEFINITIONS *****/

#define VECTOR_MINIMUM_CAPACITY 2
#define VECTOR_GROWTH_FACTOR 2
#define VECTOR_SHRINK_THRESHOLD (1 / 4)

#define VECTOR_ERROR -1
#define VECTOR_SUCCESS 0

#define VECTOR_UNINITIALIZED NULL
#define VECTOR_INITIALIZER \
	{ 0, 0, 0, VECTOR_UNINITIALIZED }

/***** STRUCTURES *****/

typedef struct _Vector {
	ULONG size;
	ULONG capacity;
	ULONG element_size;

	LONG_PTR data;
} Vector;

typedef struct _Iterator {
	LONG_PTR pointer;
	ULONG element_size;
} Iterator;


/***** METHODS *****/

/* Constructor */
int vector_setup(Vector* vector, ULONG capacity, ULONG element_size);

/* Copy Constructor */
int vector_copy(Vector* destination, Vector* source);

/* Copy Assignment */
int vector_copy_assign(Vector* destination, Vector* source);

/* Move Constructor */
int vector_move(Vector* destination, Vector* source);

/* Move Assignment */
int vector_move_assign(Vector* destination, Vector* source);

int vector_swap(Vector* destination, Vector* source);

/* Destructor */
int vector_destroy(Vector* vector);

/* Insertion */
int vector_push_back(Vector* vector, void* element);
int vector_push_front(Vector* vector, void* element);
int vector_insert(Vector* vector, ULONG index, void* element);
int vector_assign(Vector* vector, ULONG index, void* element);

/* Deletion */
int vector_pop_back(Vector* vector);
int vector_pop_front(Vector* vector);
int vector_erase(Vector* vector, ULONG index);
int vector_clear(Vector* vector);

/* Lookup */
void* vector_get(Vector* vector, ULONG index);
const void* vector_const_get(const Vector* vector, ULONG index);
void* vector_front(Vector* vector);
void* vector_back(Vector* vector);
#define VECTOR_GET_AS(type, vector_pointer, index) \
	*((type*)vector_get((vector_pointer), (index)))

/* Information */
NTSTATUS vector_is_initialized(const Vector* vector);
ULONG vector_byte_size(const Vector* vector);
ULONG vector_free_space(const Vector* vector);
NTSTATUS vector_is_empty(const Vector* vector);

/* Memory management */
int vector_resize(Vector* vector, ULONG new_size);
int vector_reserve(Vector* vector, ULONG minimum_capacity);
int vector_shrink_to_fit(Vector* vector);

/* Iterators */
Iterator vector_begin(Vector* vector);
Iterator vector_end(Vector* vector);
Iterator vector_iterator(Vector* vector, ULONG index);

void* iterator_get(Iterator* iterator);
#define ITERATOR_GET_AS(type, iterator) *((type*)iterator_get((iterator)))

int iterator_erase(Vector* vector, Iterator* iterator);

void iterator_increment(Iterator* iterator);
void iterator_decrement(Iterator* iterator);

void* iterator_next(Iterator* iterator);
void* iterator_previous(Iterator* iterator);

NTSTATUS iterator_equals(Iterator* first, Iterator* second);
NTSTATUS iterator_is_before(Iterator* first, Iterator* second);
NTSTATUS iterator_is_after(Iterator* first, Iterator* second);

ULONG iterator_index(Vector* vector, Iterator* iterator);

#define VECTOR_FOR_EACH(vector_pointer, iterator_name)           \
	for (Iterator(iterator_name) = vector_begin((vector_pointer)), \
			end = vector_end((vector_pointer));                        \
			 !iterator_equals(&(iterator_name), &end);                 \
			 iterator_increment(&(iterator_name)))

/***** PRIVATE *****/

#define MAX(a, b) ((a) > (b) ? (a) : (b))

NTSTATUS _vector_should_grow(Vector* vector);
NTSTATUS _vector_should_shrink(Vector* vector);

ULONG _vector_free_bytes(const Vector* vector);
void* _vector_offset(Vector* vector, ULONG index);
const void* _vector_const_offset(const Vector* vector, ULONG index);

void _vector_assign(Vector* vector, ULONG index, void* element);

int _vector_move_right(Vector* vector, ULONG index);
void _vector_move_left(Vector* vector, ULONG index);

int _vector_adjust_capacity(Vector* vector);
int _vector_reallocate(Vector* vector, ULONG new_capacity);

void _vector_swap(ULONG* first, ULONG* second);

#endif /* VECTOR_H */
