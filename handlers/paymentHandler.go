package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"toolsedenauth/utils"

	"github.com/gin-gonic/gin"
)

type RequestPayload struct {
	Prompt            string `json:"prompt"`
	GoFast            bool   `json:"go_fast"`
	Megapixels        string `json:"megapixels"`
	NumOutputs        int    `json:"num_outputs"`
	AspectRatio       string `json:"aspect_ratio"`
	OutputFormat      string `json:"output_format"`
	OutputQuality     int    `json:"output_quality"`
	NumInferenceSteps int    `json:"num_inference_steps"`
}

type APIResponseData struct {
	Output []string `json:"output"` // Assuming `output` is an array of image URLs
}

func generateUniqueFilename(extension string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%d_%06d.%s", time.Now().Unix(), r.Intn(1000000), extension)
}
func ImageHandler(c *gin.Context) {
	// Initialize API client
	apiClient := utils.NewAPIClient()

	var payload RequestPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JSON body: " + err.Error()})
		return
	}

	apiKey := os.Getenv("IMAGE_GEN_API_KEY")
	apiURL := os.Getenv("IMAGE_API_BASE_URL")

	if apiKey == "" || apiURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "API key or base URL not set in environment variables"})
		return
	}

	// Construct headers
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", apiKey),
	}

	response, err := apiClient.Post(apiURL, payload, headers)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to call external API: " + err.Error()})
		return
	}

	// Parse the response
	var responseData APIResponseData
	if err := json.Unmarshal(response.Body, &responseData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse API response"})
		return
	}

	// Extract the first image URL from the response
	if len(responseData.Output) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No image URL found in the response"})
		return
	}

	imageURL := responseData.Output[0]

	// Download the image and save locally
	imageResp, err := http.Get(imageURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download image"})
		return
	}
	defer imageResp.Body.Close()

	// Create the uploads directory if it doesn't exist
	uploadsDir := "uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		if err := os.Mkdir(uploadsDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create uploads directory"})
			return
		}
	}

	// Generate a unique filename for the downloaded image
	uniqueFilename := generateUniqueFilename("webp") // Assuming the format is webp as per the API
	imagePath := filepath.Join(uploadsDir, uniqueFilename)

	// Create a new file on the local disk
	outFile, err := os.Create(imagePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save image locally"})
		return
	}
	defer outFile.Close()

	// Copy the downloaded image data to the file
	_, err = outFile.ReadFrom(imageResp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save image"})
		return
	}

	// Respond with success
	c.JSON(http.StatusOK, gin.H{
		"message":  "Image saved successfully",
		"filePath": imagePath,
	})
}
