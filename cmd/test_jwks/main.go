package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
)

func main() {
	fmt.Println("Connecting to localhost:50051...")
	conn, err := grpc.NewClient("localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	fmt.Println("Connected successfully!")

	client := pb.NewTokenServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Calling GetJWKS...")
	resp, err := client.GetJWKS(ctx, &pb.GetJWKSRequest{})
	if err != nil {
		log.Fatalf("GetJWKS failed: %v", err)
	}

	fmt.Println("JWKS Response:")
	fmt.Println(resp.GetJwksJson())
}
