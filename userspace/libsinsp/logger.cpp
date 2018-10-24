/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#ifndef _WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <stdarg.h>
#include "sinsp.h"
#include "sinsp_int.h"

const size_t ENCODE_LEN = sizeof(uint64_t);

///////////////////////////////////////////////////////////////////////////////
// sinsp_logger implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_logger::sinsp_logger()
{
	m_file = NULL;
	m_flags = OT_NONE;
	m_sev = SEV_INFO;
	m_callback = NULL;
}

sinsp_logger::~sinsp_logger()
{
	if(m_file)
	{
		ASSERT(m_flags & sinsp_logger::OT_FILE);
		fclose(m_file);
	}
}

void sinsp_logger::set_log_output_type(sinsp_logger::output_type log_output_type)
{
	// Store these values and clear them so we can do other bit tests
	bool include_ts = (log_output_type & OT_NOTS) == 0;
	bool include_sev = log_output_type & OT_ENCODE_SEV;
	auto clear_formatting_bits = log_output_type &
		~(OT_NOTS | OT_ENCODE_SEV);
	log_output_type = output_type(clear_formatting_bits);

	if (log_output_type == OT_NONE)
	{
		ASSERT(false);
		throw sinsp_exception("no valid log destination found");
	}

	// OT_CALLBACK must be set through add_callback_log()
	if (log_output_type & OT_CALLBACK)
	{
		ASSERT(false);
		throw sinsp_exception("invalid call to set OT_CALLBACK flag");
	}

	auto valid_mask = OT_STDOUT | OT_STDERR | OT_FILE;
	if (log_output_type & output_type(~valid_mask))
	{
		ASSERT(false);
		throw sinsp_exception("invalid log output type");
	}

	if(log_output_type & OT_FILE)
	{
		// This may throw, so do it before stdout/stderr
		add_file_log("sinsp.log");
	}
	if(log_output_type & OT_STDOUT)
	{
		add_stdout_log();
	}
	if(log_output_type & OT_STDERR)
	{
		add_stderr_log();
	}

	// If we make it here without an exception,
	// set the bits controlling output format
	include_timestamp(include_ts);
	include_severity(include_sev);
}

void sinsp_logger::add_stdout_log()
{
	ASSERT((m_flags & sinsp_logger::OT_STDERR) == 0);

	m_flags |= sinsp_logger::OT_STDOUT;
}

void sinsp_logger::add_stderr_log()
{
	ASSERT((m_flags & sinsp_logger::OT_STDOUT) == 0);

	m_flags |= sinsp_logger::OT_STDERR;
}

void sinsp_logger::add_file_log(string filename)
{
	ASSERT(m_file == NULL);

	m_file = fopen(filename.c_str(), "w");
	if(!m_file)
	{
		throw sinsp_exception("unable to open file " + filename + " for writing");
	}

	m_flags |= sinsp_logger::OT_FILE;
}

void sinsp_logger::add_callback_log(sinsp_logger_callback callback)
{
	ASSERT(m_callback == NULL);
	m_callback = callback;
	m_flags |= sinsp_logger::OT_CALLBACK;
}

void sinsp_logger::remove_callback_log()
{
	m_callback = 0;
	m_flags &= ~sinsp_logger::OT_CALLBACK;
}

void sinsp_logger::include_timestamp(bool enable)
{
	if (enable)
	{
		m_flags &= ~OT_NOTS;
	}
	else
	{
		m_flags |= OT_NOTS;
	}
}

void sinsp_logger::include_severity(bool enable)
{
	if (enable)
	{
		m_flags |= OT_ENCODE_SEV;
	}
	else
	{
		m_flags &= ~OT_ENCODE_SEV;
	}
}

void sinsp_logger::set_severity(severity sev)
{
	if(m_sev < SEV_MIN || m_sev > SEV_MAX)
	{
		throw sinsp_exception("invalid log severity");
	}

	m_sev = sev;
}

sinsp_logger::severity sinsp_logger::get_severity() const
{
	return m_sev;
}

void sinsp_logger::log(string msg, event_severity sev)
{
	if(is_callback())
	{
		(*m_callback)(std::move(msg), (uint32_t)sev);
	}
}

void sinsp_logger::log(string msg, severity sev)
{
	if((sev > m_sev) || is_user_event(sev))
	{
		return;
	}

	size_t prefix_len = 0;
	if(m_flags & sinsp_logger::OT_ENCODE_SEV)
	{
		static_assert(ENCODE_LEN+1 < sizeof(m_tbuf), "ENCODE_LEN too big");
		snprintf(m_tbuf, ENCODE_LEN+1, "%s", encode_severity(sev));
		prefix_len += ENCODE_LEN;
	}
	if((m_flags & sinsp_logger::OT_NOTS) == 0)
	{
		struct timeval ts;
		gettimeofday(&ts, NULL);
		time_t rawtime = ts.tv_sec;
		struct tm* time_info = gmtime(&rawtime);
		size_t buf_len = sizeof(m_tbuf) - prefix_len;

		int nwritten = snprintf(&m_tbuf[prefix_len], buf_len, "%.2d-%.2d %.2d:%.2d:%.2d.%.6d ",
			time_info->tm_mon + 1,
			time_info->tm_mday,
			time_info->tm_hour,
			time_info->tm_min,
			time_info->tm_sec,
			(int)ts.tv_usec);

		ASSERT(nwritten < buf_len);
		prefix_len += nwritten;
	}
	if (prefix_len > 0)
	{
		msg.insert(0, m_tbuf, prefix_len);
	}

	if(is_callback() && m_callback)
	{
		(*m_callback)(std::move(msg), (uint32_t)sev);
	}
	else if((m_flags & sinsp_logger::OT_FILE) && m_file)
	{
		fprintf(m_file, "%s\n", msg.c_str());
		fflush(m_file);
	}
	else if(m_flags & sinsp_logger::OT_STDOUT)
	{
		fprintf(stdout, "%s\n", msg.c_str());
		fflush(stdout);
	}
	else if(m_flags & sinsp_logger::OT_STDERR)
	{
		fprintf(stderr, "%s\n", msg.c_str());
		fflush(stderr);
	}
}

char* sinsp_logger::format(severity sev, const char* fmt, ...)
{
	if(!is_callback() && is_user_event(sev))
	{
		m_tbuf[0] = '\0';
		return m_tbuf;
	}

	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m_tbuf, sizeof(m_tbuf), fmt, ap);
	va_end(ap);

	log(m_tbuf, sev);

	return m_tbuf;
}

char* sinsp_logger::format(const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m_tbuf, sizeof(m_tbuf), fmt, ap);
	va_end(ap);

	log(m_tbuf, SEV_INFO);

	return m_tbuf;
}

namespace {
// All severity strings should be ENCODE_LEN chars long
const char* sev_levels[] = {
	"SEV_DEF ",
	"SEV_FAT ",
	"SEV_CRI ",
	"SEV_ERR ",
	"SEV_WAR ",
	"SEV_NOT ",
	"SEV_INF ",
	"SEV_DEB ",
	"SEV_TRA "
};

static_assert(sizeof(sev_levels) == sizeof(*sev_levels) * ((size_t)(sinsp_logger::severity::SEV_MAX) + 1),
	"severity array must have SEV_MAX+1 elements");
}

const char *sinsp_logger::encode_severity(const severity sev)
{
	const char* ret;
	auto sev_int = (size_t)sev;
	if (sev_int > SEV_MAX)
	{
		sev_int = 0;
	}

	ret = sev_levels[sev_int];
	assert(strlen(ret) == ENCODE_LEN);
	return ret;
}

size_t sinsp_logger::decode_severity(const std::string &str, severity& sev)
{
	if(str.length() < ENCODE_LEN)
	{
		return 0;
	}

	uint64_t msg_level = *((uint64_t*)str.c_str());

	// we don't really expect "SEV_DEF " messages
	for(size_t i = 1; i <= SEV_MAX; ++i)
	{
		uint64_t level = *((uint64_t*) sev_levels[i]);
		if(msg_level == level)
		{
			sev = static_cast<severity>(i);
			return ENCODE_LEN;
		}
	}

	return 0;
}
