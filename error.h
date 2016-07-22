#pragma once
#include <stdexcept>
#include <string>
#include <SimuTrace.h>
#include <capstone/capstone.h>

class VMIException : public std::exception {
   public:
    VMIException(std::string w) : w(w){};

    const char* what() const throw() override { return w.c_str(); }

   private:
    std::string w;
};

class SimuTraceException : public std::exception {
   public:
    SimuTraceException() { SimuTrace::StGetLastError(&info); }

    const char* what() const throw() override { return info.message; }

   private:
    SimuTrace::ExceptionInformation info;
};

class CapstoneException : public std::exception {
   public:
    CapstoneException(csh handle) {
        err = cs_errno(handle);
        w = cs_strerror(err);
    }

    const char* what() const throw() override { return w.c_str(); }

   private:
    cs_err err;
    std::string w;
};
