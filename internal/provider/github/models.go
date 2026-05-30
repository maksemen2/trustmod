package github

import "time"

type repoResponse struct {
	FullName        string       `json:"full_name"`
	HTMLURL         string       `json:"html_url"`
	Archived        bool         `json:"archived"`
	ArchivedAt      *time.Time   `json:"-"`
	StargazersCount int          `json:"stargazers_count"`
	PushedAt        *time.Time   `json:"pushed_at"`
	UpdatedAt       *time.Time   `json:"updated_at"`
	License         *repoLicense `json:"license"`
}

type repoLicense struct {
	SPDXID string `json:"spdx_id"`
	Name   string `json:"name"`
}

type graphqlRepoResponse struct {
	Data struct {
		Repository *graphqlRepository `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type graphqlRepository struct {
	NameWithOwner  string              `json:"nameWithOwner"`
	URL            string              `json:"url"`
	IsArchived     bool                `json:"isArchived"`
	ArchivedAt     *time.Time          `json:"archivedAt"`
	StargazerCount int                 `json:"stargazerCount"`
	PushedAt       *time.Time          `json:"pushedAt"`
	LicenseInfo    *graphqlLicenseInfo `json:"licenseInfo"`
}

type graphqlLicenseInfo struct {
	SPDXID string `json:"spdxId"`
	Name   string `json:"name"`
}
