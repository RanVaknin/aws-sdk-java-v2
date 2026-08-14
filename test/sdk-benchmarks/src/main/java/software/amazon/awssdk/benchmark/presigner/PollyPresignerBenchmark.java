/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package software.amazon.awssdk.benchmark.presigner;

import java.net.URI;
import java.net.URL;
import java.time.Duration;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.polly.model.OutputFormat;
import software.amazon.awssdk.services.polly.model.SynthesizeSpeechRequest;
import software.amazon.awssdk.services.polly.presigner.PollyPresigner;
import software.amazon.awssdk.services.polly.presigner.model.PresignedSynthesizeSpeechRequest;
import software.amazon.awssdk.services.polly.presigner.model.SynthesizeSpeechPresignRequest;

@State(Scope.Thread)
public class PollyPresignerBenchmark {
    private static final String ENDPOINT = "polly.us-east-1.amazonaws.com";

    private PollyPresigner presigner;
    private SynthesizeSpeechPresignRequest request;

    @Setup(Level.Trial)
    public void setup() {
        presigner = PollyPresigner.builder()
                                 .region(Region.US_EAST_1)
                                 .credentialsProvider(StaticCredentialsProvider.create(
                                     AwsBasicCredentials.create("access-key", "secret-key")))
                                 .endpointOverride(URI.create("https://" + ENDPOINT))
                                 .build();

        SynthesizeSpeechRequest synthesizeSpeechRequest =
            SynthesizeSpeechRequest.builder()
                                   .voiceId("Joanna")
                                   .outputFormat(OutputFormat.MP3)
                                   .sampleRate("22050")
                                   .textType("text")
                                   .text("This is a representative Polly presigner benchmark request.")
                                   .build();

        request = SynthesizeSpeechPresignRequest.builder()
                                                .signatureDuration(Duration.ofMinutes(15))
                                                .synthesizeSpeechRequest(synthesizeSpeechRequest)
                                                .build();

        validate(presigner.presignSynthesizeSpeech(request));
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        presigner.close();
    }

    @Benchmark
    public PresignedSynthesizeSpeechRequest presignSynthesizeSpeech() {
        return presigner.presignSynthesizeSpeech(request);
    }

    private static void validate(PresignedSynthesizeSpeechRequest result) {
        URL url = result.url();
        if (!"https".equals(url.getProtocol())
            || !ENDPOINT.equals(url.getHost())
            || !"/v1/speech".equals(url.getPath())
            || url.getQuery() == null
            || !url.getQuery().contains("X-Amz-Signature=")) {
            throw new IllegalStateException("Polly presigner benchmark sanity check failed: " + url);
        }
    }
}
