#include <optional>
#include <DataTypes/DataTypesNumber.h>
#include <Functions/FunctionFactory.h>
#include <Functions/FunctionHelpers.h>
#include <Functions/FunctionTokens.h>
#include <Common/Exception.h>

#include <Poco/UTF8Encoding.h>
#include <zlib.h>

namespace DB
{

namespace ErrorCodes
{
extern const int BAD_ARGUMENTS;
extern const int ILLEGAL_COLUMN;
extern const int ILLEGAL_TYPE_OF_ARGUMENT;
extern const int NUMBER_OF_ARGUMENTS_DOESNT_MATCH;
}

/** Functions that finds all substrings win minimal length n
  * such their border (n-1)-grams' hashes are more than hashes of every (n-1)-grams' in substring.
  * As a hash function use zlib crc32, which is crc32-ieee with 0xffffffff as initial value
  *
  * sparseGrams(s)
  */
namespace
{

using Pos = const char *;

template <bool is_utf8>
class SparseGramsImpl
{
private:
    Pos pos;
    Pos end;
    std::vector<UInt32> ngram_hashes;
    std::vector<size_t> utf8_offsets;
    size_t left;
    size_t right;
    UInt64 min_ngram_length = 3;

    void buildNgramHashes()
    {
        if constexpr (is_utf8)
        {
            Poco::UTF8Encoding encoder{};
            size_t byte_offset = 0;
            while (pos + byte_offset < end)
            {
                utf8_offsets.push_back(byte_offset);
                auto len = encoder.sequenceLength(reinterpret_cast<const unsigned char *>(pos + byte_offset), end - pos - byte_offset);
                if (len < 1)
                    throw Exception(ErrorCodes::BAD_ARGUMENTS, "Incorrect utf8 symbol");
                byte_offset += len;
            }
            utf8_offsets.push_back(byte_offset);

            for (size_t i = 0; i + min_ngram_length - 1 < utf8_offsets.size(); ++i)
                ngram_hashes.push_back(crc32_z(0UL, reinterpret_cast<const unsigned char *>(pos + utf8_offsets[i]), utf8_offsets[i + min_ngram_length - 1] - utf8_offsets[i]));
        }
        else
        {
            for (size_t i = 0; pos + i + min_ngram_length - 2 < end; ++i)
                ngram_hashes.push_back(crc32_z(0L, reinterpret_cast<const unsigned char *>(pos + i), min_ngram_length - 1));
        }
    }

    std::optional<std::pair<size_t, size_t>> getNextIndices()
    {
        while (left < ngram_hashes.size())
        {
            while (right < ngram_hashes.size())
            {
                if (right - left > 1)
                {
                    if (ngram_hashes[left] < ngram_hashes[right - 1])
                        break;

                    if (ngram_hashes[right] < ngram_hashes[right - 1])
                    {
                        ++right;
                        continue;
                    }
                }

                return {{left, right++}};
            }
            ++left;
            right = left + 1;
        }

        return std::nullopt;
    }

public:
    static constexpr auto name = is_utf8 ? "sparseGramsUTF8" : "sparseGrams";
    static constexpr auto strings_argument_position = 0uz;
    static bool isVariadic() { return true; }
    static size_t getNumberOfArguments() { return 0; }
    static ColumnNumbers getArgumentsThatAreAlwaysConstant() { return {1}; }

    static void checkArguments(const IFunction & func, const ColumnsWithTypeAndName & arguments)
    {
        FunctionArgumentDescriptors mandatory_args{
            {"s", static_cast<FunctionArgumentDescriptor::TypeValidator>(&isString), nullptr, "String"},
        };

        FunctionArgumentDescriptors optional_args{
            {"min_ngram_length", static_cast<FunctionArgumentDescriptor::TypeValidator>(&isNativeInteger), isColumnConst, "const Number"},
        };

        validateFunctionArguments(func, arguments, mandatory_args, optional_args);
    }

    void init(const ColumnsWithTypeAndName & arguments, bool /*max_substrings_includes_remaining_string*/)
    {
        if (arguments.size() > 2)
            throw Exception(
                ErrorCodes::NUMBER_OF_ARGUMENTS_DOESNT_MATCH,
                "Number of arguments for function {} doesn't match: passed {}",
                name,
                arguments.size());

        if (arguments.size() == 2)
            min_ngram_length = arguments[1].column->getUInt(0);

        if (min_ngram_length < 3)
            throw Exception(ErrorCodes::BAD_ARGUMENTS, "Argument 'min_ngram_length' must be greater or equal to 3");
    }

    /// Called for each next string.
    void set(Pos pos_, Pos end_)
    {
        pos = pos_;
        end = end_;
        left = 0;
        right = 1;

        if constexpr (is_utf8)
            utf8_offsets.clear();

        buildNgramHashes();
    }

    /// Get the next token, if any, or return false.
    bool get(Pos & token_begin, Pos & token_end)
    {
        auto result = getNextIndices();
        if (!result)
            return false;

        auto [iter_left, iter_right] = *result;

        if constexpr (is_utf8)
        {
            token_begin = pos + utf8_offsets[iter_left];
            token_end = pos + utf8_offsets[iter_right + min_ngram_length - 1];
        }
        else
        {
            token_begin = pos + iter_left;
            token_end = pos + iter_right + min_ngram_length - 1;
        }
        return true;
    }
};

template <bool is_utf8>
class SparseGramsHashes : public IFunction
{
public:
    static constexpr auto name = is_utf8 ? "sparseGramsHashesUTF8" : "sparseGramsHashes";
    String getName() const override { return name; }
    bool isVariadic() const override { return true; }
    size_t getNumberOfArguments() const override { return 0; }
    bool isSuitableForShortCircuitArgumentsExecution(const DataTypesWithConstInfo & /*arguments*/) const override { return true; }
    bool useDefaultImplementationForConstants() const override { return true; }
    static FunctionPtr create(ContextPtr) { return std::make_shared<SparseGramsHashes>(); }
    ColumnNumbers getArgumentsThatAreAlwaysConstant() const override { return {1}; }

    DataTypePtr getReturnTypeImpl(const ColumnsWithTypeAndName & args) const override
    {
        impl.checkArguments(*this, args);
        return std::make_shared<DataTypeArray>(std::make_shared<DataTypeUInt32>());
    }

    ColumnPtr executeImpl(const ColumnsWithTypeAndName & arguments, const DataTypePtr &, size_t input_rows_count) const override
    {
        impl.init(arguments, false);

        auto col_res_nested = ColumnUInt32::create();
        auto & res_nested_data = col_res_nested->getData();

        auto col_res_offsets = ColumnArray::ColumnOffsets::create();
        auto & res_offsets_data = col_res_offsets->getData();
        res_offsets_data.reserve(input_rows_count);

        const auto & src = arguments[0];
        const auto & src_column = *src.column;

        if (const auto * col_non_const = typeid_cast<const ColumnString *>(&src_column))
        {
            for (size_t i = 0; i < input_rows_count; ++i)
            {
                std::vector<UInt32> row_result = getHashes(col_non_const->getDataAt(i).toView());
                res_nested_data.insert(row_result.begin(), row_result.end());
                res_offsets_data.push_back(row_result.size());
            }
        }
        else
            throw Exception(ErrorCodes::ILLEGAL_TYPE_OF_ARGUMENT, "Illegal argument for function {}", name);

        return ColumnArray::create(std::move(col_res_nested), std::move(col_res_offsets));
    }

private:
    std::vector<UInt32> getHashes(std::string_view input_str) const
    {
        impl.set(input_str.data(), input_str.data() + input_str.size());

        std::vector<UInt32> result;
        result.reserve(input_str.size()); // Reserve at least for every (n-1)gram

        Pos start{};
        Pos end{};
        for (bool has_data = impl.get(start, end); has_data; has_data = impl.get(start, end))
            result.push_back(crc32_z(0UL, reinterpret_cast<const unsigned char *>(start), end - start));

        return result;
    }

    mutable SparseGramsImpl<is_utf8> impl;
};

using FunctionSparseGrams = FunctionTokens<SparseGramsImpl<false>>;
using FunctionSparseGramsUTF8 = FunctionTokens<SparseGramsImpl<true>>;

}

REGISTER_FUNCTION(SparseGrams)
{
    factory.registerFunction<FunctionSparseGrams>();
    factory.registerFunction<FunctionSparseGramsUTF8>();

    factory.registerFunction<SparseGramsHashes<false>>();
    factory.registerFunction<SparseGramsHashes<true>>();
}

}
