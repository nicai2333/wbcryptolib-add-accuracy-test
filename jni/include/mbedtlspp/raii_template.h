/**
* templates to DRY the RAII type declaration
*/
#ifndef MBEDTLSPP_RAII_TEMPLATE_H_
#define MBEDTLSPP_RAII_TEMPLATE_H_

/**
* raii_template handles all the boilerplate for a RAII copiable/movable type
*/

template<typename metadata>
struct uncopyable_raii_template: private metadata {

	using raw_type = typename metadata::raw_type;

	raw_type value;

	uncopyable_raii_template() { init_func(&value); }
	~uncopyable_raii_template() { free_func(&value); }
	uncopyable_raii_template(const uncopyable_raii_template& other) = delete;
	uncopyable_raii_template& operator=(const uncopyable_raii_template& other) = delete;
	uncopyable_raii_template(uncopyable_raii_template&& other) {
		init_func(&value);
		move(other.value, this->value);
	}
	uncopyable_raii_template& operator=(uncopyable_raii_template&& other) {
		move(other.value, this->value);
		return *this;
	}

	raw_type* ptr() { return &value; }

	const raw_type* ptr() const { return &value; }

	raw_type* operator->() { return &value; }

	const raw_type* operator->() const { return &value; }

	void move_from(raw_type& from) {
		move(from, this->value);
	}

	void move_into(raw_type& to) {
		move(this->value, to);
	}

	private:

	void move(raw_type& from, raw_type& to) {
		if (&from == &to) {
			return;
		}
		free_func(&to);
		to = from;
		init_func(&from);
	}

};

template<typename metadata>
struct copyable_raii_template: private metadata {

	using raw_type = typename metadata::raw_type;

	raw_type value;

	copyable_raii_template() { init_func(&value); }
	~copyable_raii_template() { free_func(&value); }
	copyable_raii_template(const copyable_raii_template& other) {
		init_func(&value);
		copy(other.value, this->value);
	}
	copyable_raii_template& operator=(const copyable_raii_template& other) {
		copy(other.value, this->value);
		return *this;
	}
	copyable_raii_template(copyable_raii_template&& other) {
		init_func(&value);
		move(other.value, this->value);
	}
	copyable_raii_template& operator=(copyable_raii_template&& other) {
		move(other.value, this->value);
		return *this;
	}

	raw_type* ptr() { return &value; }

	const raw_type* ptr() const { return &value; }

	raw_type* operator->() { return &value; }

	const raw_type* operator->() const { return &value; }

	void move_from(raw_type& from) {
		move(from, this->value);
	}

	void move_into(raw_type& to) {
		move(this->value, to);
	}

	void copy_from(const raw_type& from) {
		copy(from, this->value);
	}

	void copy_into(raw_type& to) const {
		copy(this->value, to);
	}

	private:

	void copy(const raw_type& from, raw_type& to) {
		raw_type val;
		init_func(&val);
		copy_func(&val, &from);
		free_func(&to);
		to = val;
	}

	void move(raw_type& from, raw_type& to) {
		if (&to == &from) {
			return;
		}
		free_func(&to);
		to = from;
		init_func(&from);
	}

};

//usage macro, use the templates like this, this uses CRTP pattern 
//for static polymorphism 

#define MBEDTLSPP_DEFINE_RAII_METADATA(struct_name, to_wrap, init_fun, free_fun)\
	struct struct_name##_metadata {          \
		using raw_type = to_wrap;                                              \
		void init_func(raw_type* t) { init_fun(t); }                           \
		void free_func(raw_type* t) { free_fun(t); }                           \
	};

#define MBEDTLSPP_DEFINE_COPYABLE_RAII_METADATA(struct_name, to_wrap, init_fun, copy_fun, free_fun)\
	struct struct_name##_metadata {                  \
		using raw_type = to_wrap;                                                    \
		void init_func(raw_type* t) { init_fun(t); }                                 \
		void copy_func(raw_type* dst, const raw_type* src) { copy_fun(dst, src); }   \
		void free_func(raw_type* t) { free_fun(t); }                                 \
	};

#endif