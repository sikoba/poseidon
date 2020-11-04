require "big"
require "ecdsa"
require "./poseidon_parameters.cr"


def mult(vec, mat)
    res = Array(BigInt).new();
    ll = vec.size();
    (0...vec.size()).each do |j|
        s = BigInt.new(0);
        (0...vec.size()).each do |i|
            s += vec[i]*mat[i][j]
        end
        res.push(s)
    end
    return res;
end


class Poseidon
    @state : Array(BigInt);
    @rate : Int32     # r
    @prime : BigInt

    def perm(state_words, params : PoseidonParams)
        t = state_words.size();
        n = Math.log(@prime, 2).ceil;
        round_constants_field = params.round_constants();
        mds_matrix = params.mds_matrix();
        
        r_ff = params.@full_rounds // 2;
        round_constants_counter = 0
        # First full rounds
        (0...r_ff).each do |r|
            # Round constants, nonlinear layer, matrix multiplication
            (0...t).each do |i|
                state_words[i] = (state_words[i] + round_constants_field[round_constants_counter]).modulo(@prime)
                round_constants_counter += 1
            end
            (0...t).each do |i|
                state_words[i] = ECDSA::Math.mod_exp(state_words[i], BigInt.new(5), @prime);
            end
            state_words = mult(state_words, mds_matrix);
        end

        # Middle partial rounds
        (0...params.@partial_rounds).each do |r|
            # Round constants, nonlinear layer, matrix multiplication
            (0...t).each do |i|
                state_words[i] = state_words[i] + round_constants_field[round_constants_counter]
                round_constants_counter += 1
            end
            state_words[0] = ECDSA::Math.mod_exp(state_words[0], BigInt.new(5), @prime);
            state_words = mult(state_words, mds_matrix);
        end

        # Last-1 full rounds (no matrix multiplication at last round)
        (0...r_ff-1).each do |r|
            # Round constants, nonlinear layer, matrix multiplication
            (0...t).each do |i|
                state_words[i] = state_words[i] + round_constants_field[round_constants_counter]
                round_constants_counter += 1
            end
            (0...t).each do |i|
                state_words[i] = ECDSA::Math.mod_exp(state_words[i], BigInt.new(5), @prime);
            end
            state_words = mult(state_words, mds_matrix);
            #state_words = state_words * MDS_matrix_field;     faut un 'vecteur' 1 
        end

        # Last round (no matrix multiplication)
        # Round constants, nonlinear layer
        (0...t).each do |i|
            state_words[i] = state_words[i] + round_constants_field[round_constants_counter]
            round_constants_counter += 1
        end
        (0...t).each do |i|
            state_words[i] = ECDSA::Math.mod_exp(state_words[i], BigInt.new(5), @prime);
        end
        return state_words
    end

    # number of bytes that can fit in a field element
    def field_size
        return ((Math.log(@prime, 2)).ceil.to_i - 1 )// 8;
    end

    #convert k elements to field
    def to_field(data : Array(UInt8), k)
        result = Array(BigInt).new();
        data.each_slice(k) do |slice|
            result += Poseidon.bytes_to_field(slice);
        end
        return result
    end

    # Convert an array of field elements to bytes
    def to_byte(field_data : Array(BigInt))
        result = Array(UInt8).new();
        field_data.each do |f|
            result += Poseidon.field_to_bytes(f);
        end
        return result;
    end

    # field prime number, desired security bits, t (permutation width)
    def initialize(@prime, security, width = 0, capacity = -1)
        if (capacity == -1)
            capacity = compute_capacity(security);
        end
        if (width == 0)
            width = Math.min(3*capacity, 5)            # SWAG
        end
        # Rate, in field elements
        @rate = width - capacity;
        pp "Poseidon initialized with capacity #{capacity} and rate #{@rate}"

        @state = Array(BigInt).new(width, BigInt.new(0));
    end

    # compute the capacity in order to achieve the desired security
    # WARNING - we allow for a 5% tolerance, use strict=true to ensure desired security
    def compute_capacity(security, strict = false)
        n = field_size(); #number of bytes that can fit in a field element
        # Capacity:
        c = security //(4*n)        #capacity in field elements
        s = security;
        if (!strict)
            s = security*0.95 # 5% margin
        end
        while 4*c*n <  s
            c += 1
        end
        return c;
    end

    def hash(data : Array(UInt8), hash_size, params : PoseidonParams)
        chunks = preprocess(data);
        absorb(chunks, params);
        return squeeze(hash_size, params);
    end

    def auto_parameters(security = 128)
        params = PoseidonParams.new()
        params.compute_best_params(@prime, @state.size(), security)
        params.init_generator();
        return params;
    end

    #convert input into arrays of field
    def preprocess(data : Array(UInt8))
        n = field_size();  #number of bytes that can fit in a field element
        l = data.size();
        result = Array(Array(BigInt)).new;
        chunk = Array(BigInt).new();
        (0...l).step(n) do |i|
            chunk.push(Poseidon.bytes_to_field(data[i,n]));
            if (chunk.size() == @rate)
                result.push(chunk);
                chunk = Array(BigInt).new();
            end
        end
        if (chunk.size() > 0 )
             #We pad with 0 the last part
             while chunk.size() < @rate
                chunk.unshift(BigInt.new(0))
             end
            result.push(chunk);
            chunk = Array(BigInt).new();
        end
        return result;
    end

    def self.bytes_to_field(data : Array(UInt8))
        s = "";
        data.each do |u|
            c = u.to_s(16);
            if (c.size == 1)
                c = "0" + c;
            end
            s += c
        end
        b = BigInt.new(s,16);
        return b;
    end

    def self.field_to_bytes(b)
        s = b.to_s(16);
        if s.size %2 == 1
            s = "0"+ s;
        end
        r = Array(UInt8).new();
        (0...s.size()-1).step(2) do |i|
           r.push(s[i,2].to_u8(16))
        end
        return r;
    end

    def absorb(chunks, params)
        chunks.each do |input|
            (0...@rate).each do |i|
                @state[i] = (@state[i] + input[i]).modulo(@prime)
            end
            @state = perm(@state, params);
        end
    end

    #size in bytes
    def squeeze(hash_size, params)
        data = to_byte(@state[0...@rate]);
        while data.size() < hash_size
            @state = perm(@state, params);
            data += to_byte(@state[0...@rate])
        end
        return data[0...hash_size];
    end
end




