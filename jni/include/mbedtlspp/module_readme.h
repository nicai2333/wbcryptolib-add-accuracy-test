/**
* Submodule: mbedtlspp
*
* this module contains the C++ Wrapper for mbedtls
*
* it does the following things:
*    * RAII wrappers so you dont have to worry about init & free
*    * wrapper has added functionalities such as serialization and system defaults
*    * all wrapper functionalities has a corresponding function so you dont have to wrap your object just to use them
*    * all in-buffer and out-buffer are replaced by array_view and buffer_view, and use exception for error report
*        so you can call them without passing a lot of parameters
*/