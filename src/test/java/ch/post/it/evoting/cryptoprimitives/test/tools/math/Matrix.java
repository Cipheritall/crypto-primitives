package ch.post.it.evoting.cryptoprimitives.test.tools.math;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Matrix {
	public static List<List<BigInteger>> transpose(List<List<BigInteger>> collect) {

		BigInteger[][] matrix = collect.stream()
				.map(o -> o.toArray(new BigInteger[0]))
				.collect(Collectors.toList())
				.toArray(new BigInteger[0][0]);

		int x = collect.size();
		int y = collect.stream().map(List::size).distinct().findFirst().get();

		BigInteger[][] transpose = new BigInteger[y][x];

		for (int i = 0; i < x; i++) {
			for (int j = 0; j < y; j++) {
				transpose[j][i] = matrix[i][j];
			}
		}

		return Arrays.stream(transpose)
				.map(Arrays::asList)
				.collect(Collectors.toList());
	}
}
