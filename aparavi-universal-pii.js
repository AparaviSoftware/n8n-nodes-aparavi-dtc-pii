/**
 * Aparavi DTC Universal - Works in both Browser and Node.js
 * 
 * This file provides a unified interface for PII anonymization that works in:
 * - Browser environments (ES modules)
 * - Node.js environments (CommonJS)
 * - Modern Node.js with ES modules
 */

// Default pipeline configuration - HIPAA
const DEFAULT_PIPELINE_CONFIG = {
    "pipeline": {
        "components": [
            {
                "id": "webhook_1",
                "provider": "webhook",
                "config": {
                    "hideForm": true,
                    "mode": "Source",
                    "type": "webhook"
                },
                "ui": {
                    "position": {
                        "x": 60,
                        "y": 220
                    },
                    "measured": {
                        "width": 140,
                        "height": 123
                    },
                    "data": {
                        "class": "source",
                        "type": "default"
                    },
                    "formDataValid": true
                }
            },
            {
                "id": "classify_1",
                "provider": "classify",
                "config": {
                    "classifications": [
                        {
                            "name": "United States Health Insurance Portability and Accountability Act (HIPAA) Policy",
                            "description": "Detects electronic patient health information (ePHI) for U.S. Health Insurance Portability and Accountability Act (HIPAA), also known as Public Law 104-191, and the Health Information Technology for Economic and Clinical Health (HITECH) Act.",
                            "policyRule": {
                                "DlpPolicyTemplate": {
                                    "Attributes": {
                                        "xmlns": "http://schemas.nucleuz.com/2013/dlp_policy"
                                    },
                                    "Metadata": [
                                        {
                                            "Attributes": {
                                                "id": "9a4e8d1d-acb9-b83c-7c46-a20a0b04825b",
                                                "formatVersion": "101"
                                            },
                                            "Name": [
                                                {
                                                    "Value": "United States Health Insurance Portability and Accountability Act (HIPAA) Policy",
                                                    "Attributes": {
                                                        "langcode": "en",
                                                        "default": "true"
                                                    }
                                                }
                                            ],
                                            "Description": [
                                                {
                                                    "Value": "Detects electronic patient health information (ePHI) for U.S. Health Insurance Portability and Accountability Act (HIPAA), also known as Public Law 104-191, and the Health Information Technology for Economic and Clinical Health (HITECH) Act.",
                                                    "Attributes": {
                                                        "langcode": "en",
                                                        "default": "true"
                                                    }
                                                }
                                            ],
                                            "Version": [
                                                {
                                                    "Attributes": {
                                                        "major": "2024",
                                                        "minor": "9",
                                                        "build": "0",
                                                        "revision": "13070"
                                                    }
                                                }
                                            ],
                                            "Categories": [
                                                {
                                                    "Locations": [
                                                        {
                                                            "Location": [
                                                                {
                                                                    "Attributes": {
                                                                        "idRef": "L6.21"
                                                                    }
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "Industries": [
                                                        {
                                                            "Industry": [
                                                                {
                                                                    "Attributes": {
                                                                        "idRef": "I3"
                                                                    }
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "Regulations_Laws": [
                                                        {
                                                            "Regulation_Law": [
                                                                {
                                                                    "Attributes": {
                                                                        "idRef": "R55"
                                                                    }
                                                                },
                                                                {
                                                                    "Attributes": {
                                                                        "idRef": "R1017"
                                                                    }
                                                                },
                                                                {
                                                                    "Attributes": {
                                                                        "idRef": "R1018"
                                                                    }
                                                                }
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "Rules": [
                                        {
                                            "Rule": [
                                                {
                                                    "Attributes": {
                                                        "id": "Default_"
                                                    },
                                                    "FormatVersion": [
                                                        {
                                                            "Attributes": {
                                                                "version": "1"
                                                            },
                                                            "Condition": [
                                                                {
                                                                    "And": [
                                                                        {
                                                                            "And": [
                                                                                {
                                                                                    "Or": [
                                                                                        {
                                                                                            "Attributes": {
                                                                                                "min": "1",
                                                                                                "earlyOut": "true"
                                                                                            },
                                                                                            "ClassificationRule": [
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "71ad74d4-f51d-1e1d-1874-7d380a66efeb",
                                                                                                        "minUniqueCount": "2"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "0bfe61d1-5e79-d849-9480-bfde26971827"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "d0ac07ef-399d-8089-40ab-b1f047fb3698",
                                                                                                        "patternMode": "withinConfidenceRange",
                                                                                                        "minConfidence": "85"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "3d50b4e2-9a9b-c71b-6302-4e6a842772fb",
                                                                                                        "patternMode": "withinConfidenceRange",
                                                                                                        "minConfidence": "85"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "703b80f6-965d-5e60-9455-d4e7058f9011"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "fdcdd309-dd6c-91a1-ea11-f06739b86027"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "fee2002d-14a3-27de-3df4-68f46cb4f504"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "b050a483-f7dd-864b-0952-3e5194e8e2ef"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "8e8b344a-b724-12c4-d8eb-007d67004d85"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "4ba027e7-8b74-dcda-5836-87e51b9b7fec"
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "idRef": "9f83aaf1-b2bc-c073-de3d-d44b98869200"
                                                                                                    }
                                                                                                }
                                                                                            ]
                                                                                        }
                                                                                    ],
                                                                                    "Not": [
                                                                                        {
                                                                                            "Or": [
                                                                                                {
                                                                                                    "ClassificationRule": [
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "6957edd0-0ff9-4064-1dca-64932ac3a7e5"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "8abafeda-959e-5c59-57d8-a2a19942419d"
                                                                                                            }
                                                                                                        }
                                                                                                    ]
                                                                                                }
                                                                                            ]
                                                                                        }
                                                                                    ]
                                                                                }
                                                                            ],
                                                                            "Or": [
                                                                                {
                                                                                    "Attributes": {
                                                                                        "min": "1",
                                                                                        "earlyOut": "true"
                                                                                    },
                                                                                    "And": [
                                                                                        {
                                                                                            "Or": [
                                                                                                {
                                                                                                    "Attributes": {
                                                                                                        "min": "2"
                                                                                                    },
                                                                                                    "ClassificationRule": [
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "02eccb09-e8e3-a23e-6a32-692843fdf547",
                                                                                                                "patternMode": "withinConfidenceRange",
                                                                                                                "minConfidence": "85"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "4781f188-f04e-a954-8480-fc670bdc4e61"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "dad63eda-045b-f4d4-91a3-11c38181e950"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "1a7b350e-0797-10aa-5716-7d3136e7ad95"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "7c65fe2e-79e7-3f19-cf33-b18228744cb9"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "e20319a5-c6ef-67c4-1b07-a14f02f38b11",
                                                                                                                "minCount": "4"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "b5d1e90c-2916-1354-845d-8a67cecc2723",
                                                                                                                "minConfidence": "85"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "7c0f72ed-2cc7-5b50-50ad-7d7d576a561c"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "87f68e9b-ca07-3b47-bb62-afd447eb7c8f",
                                                                                                                "minCount": "4"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "7ea3077a-f6ca-347a-1781-56e847ce5a22"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "b7df8e6f-9afa-ecd5-7202-291f8d25d5f6"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "efdf0e84-ea8b-44b4-40dc-f300b6db0b6b"
                                                                                                            }
                                                                                                        }
                                                                                                    ]
                                                                                                }
                                                                                            ],
                                                                                            "Not": [
                                                                                                {
                                                                                                    "Or": [
                                                                                                        {
                                                                                                            "ClassificationRule": [
                                                                                                                {
                                                                                                                    "Attributes": {
                                                                                                                        "idRef": "ae3edd33-6f09-e758-5337-472c51b35fb4"
                                                                                                                    }
                                                                                                                },
                                                                                                                {
                                                                                                                    "Attributes": {
                                                                                                                        "idRef": "86fe7e4f-0bbb-861c-031e-abfea232c22b"
                                                                                                                    }
                                                                                                                }
                                                                                                            ]
                                                                                                        }
                                                                                                    ]
                                                                                                }
                                                                                            ]
                                                                                        },
                                                                                        {
                                                                                            "Or": [
                                                                                                {
                                                                                                    "ClassificationRule": [
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "407b6e49-8d5c-16ee-841b-6771bfcbc9b3",
                                                                                                                "minConfidence": "70"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "2e41ed9e-a457-f101-7906-d71d98d4983f"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "162eae37-1a3e-2edb-51d2-7a96e9d4d732"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "8ac32a03-6b8a-01ae-82e4-012a133c6042",
                                                                                                                "patternMode": "withinConfidenceRange",
                                                                                                                "minConfidence": "85"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "222066f3-abfc-3065-5b8f-4037c1ba4398"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "dc7a8728-ed43-712a-ec1a-60a108cae6ca"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "5234f630-9c77-3b11-9333-5ffe6406b4ea"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "28454a83-a3bd-513c-cb13-6adea3b4fd28"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "1a78c925-2007-88ec-5cd2-41a8127c038d"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "06720402-39a7-fb65-c27d-c58eb3159326"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "247b8d70-6e25-7bfe-ca36-6ee82d64a7e0",
                                                                                                                "minConfidence": "75",
                                                                                                                "patternMode": "withinConfidenceRange"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "5b999c41-d73d-29c3-f6b2-98ae90128d9c"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "293093a3-54f9-e1bd-f967-0e6cf8062ff6"
                                                                                                            }
                                                                                                        },
                                                                                                        {
                                                                                                            "Attributes": {
                                                                                                                "idRef": "4bda6646-70dd-73a5-2694-42d491ae5d24"
                                                                                                            }
                                                                                                        }
                                                                                                    ]
                                                                                                }
                                                                                            ],
                                                                                            "Not": [
                                                                                                {
                                                                                                    "Or": [
                                                                                                        {
                                                                                                            "ClassificationRule": [
                                                                                                                {
                                                                                                                    "Attributes": {
                                                                                                                        "idRef": "d08aac15-e5eb-a673-baec-f2a27a1ec379"
                                                                                                                    }
                                                                                                                },
                                                                                                                {
                                                                                                                    "Attributes": {
                                                                                                                        "idRef": "62c4291a-8ccb-9209-0e06-15637830736c"
                                                                                                                    }
                                                                                                                }
                                                                                                            ]
                                                                                                        }
                                                                                                    ]
                                                                                                }
                                                                                            ]
                                                                                        }
                                                                                    ]
                                                                                }
                                                                            ]
                                                                        }
                                                                    ]
                                                                }
                                                            ],
                                                            "Actions": [
                                                                {
                                                                    "HIPAA_Content_Detected": [
                                                                        ""
                                                                    ]
                                                                }
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            },
                            "policyGuid": "9a4e8d1d-acb9-b83c-7c46-a20a0b04825b",
                            "rules": [
                                "71ad74d4-f51d-1e1d-1874-7d380a66efeb",
                                "0bfe61d1-5e79-d849-9480-bfde26971827",
                                "d0ac07ef-399d-8089-40ab-b1f047fb3698",
                                "3d50b4e2-9a9b-c71b-6302-4e6a842772fb",
                                "703b80f6-965d-5e60-9455-d4e7058f9011",
                                "fdcdd309-dd6c-91a1-ea11-f06739b86027",
                                "fee2002d-14a3-27de-3df4-68f46cb4f504",
                                "b050a483-f7dd-864b-0952-3e5194e8e2ef",
                                "02eccb09-e8e3-a23e-6a32-692843fdf547",
                                "4781f188-f04e-a954-8480-fc670bdc4e61",
                                "dad63eda-045b-f4d4-91a3-11c38181e950",
                                "1a7b350e-0797-10aa-5716-7d3136e7ad95",
                                "7c65fe2e-79e7-3f19-cf33-b18228744cb9",
                                "e20319a5-c6ef-67c4-1b07-a14f02f38b11",
                                "b5d1e90c-2916-1354-845d-8a67cecc2723",
                                "7c0f72ed-2cc7-5b50-50ad-7d7d576a561c",
                                "87f68e9b-ca07-3b47-bb62-afd447eb7c8f",
                                "407b6e49-8d5c-16ee-841b-6771bfcbc9b3",
                                "2e41ed9e-a457-f101-7906-d71d98d4983f",
                                "162eae37-1a3e-2edb-51d2-7a96e9d4d732",
                                "8ac32a03-6b8a-01ae-82e4-012a133c6042",
                                "222066f3-abfc-3065-5b8f-4037c1ba4398",
                                "dc7a8728-ed43-712a-ec1a-60a108cae6ca",
                                "5234f630-9c77-3b11-9333-5ffe6406b4ea",
                                "28454a83-a3bd-513c-cb13-6adea3b4fd28",
                                "1a78c925-2007-88ec-5cd2-41a8127c038d",
                                "06720402-39a7-fb65-c27d-c58eb3159326",
                                "247b8d70-6e25-7bfe-ca36-6ee82d64a7e0"
                            ]
                        }
                    ]
                },
                "ui": {
                    "position": {
                        "x": 260,
                        "y": 160
                    },
                    "measured": {
                        "width": 140,
                        "height": 77
                    },
                    "data": {
                        "class": "text",
                        "type": "default"
                    },
                    "formDataValid": true,
                    "edges": [
                        {
                            "selectable": true,
                            "deletable": true,
                            "id": "xy-edge__webhook_1source-text-0-classify_1target-text-0",
                            "source": "webhook_1",
                            "target": "classify_1",
                            "sourceHandle": "source-text-0",
                            "targetHandle": "target-text-0"
                        }
                    ]
                },
                "input": [
                    {
                        "lane": "text",
                        "from": "webhook_1"
                    }
                ]
            },
            {
                "id": "anonymize_text_1",
                "provider": "anonymize_text",
                "config": {
                    "profile": "glinerMergedLarge",
                    "glinerMergedLarge": {
                        "anonymizeChar": "█"
                    }
                },
                "ui": {
                    "position": {
                        "x": 460,
                        "y": 260
                    },
                    "measured": {
                        "width": 140,
                        "height": 90
                    },
                    "data": {
                        "class": "text",
                        "type": "default"
                    },
                    "formDataValid": true,
                    "edges": [
                        {
                            "selectable": true,
                            "deletable": true,
                            "id": "xy-edge__classify_1source-classifications-0-anonymize_text_1target-classifications-0",
                            "source": "classify_1",
                            "target": "anonymize_text_1",
                            "sourceHandle": "source-classifications-0",
                            "targetHandle": "target-classifications-0"
                        },
                        {
                            "selectable": true,
                            "deletable": true,
                            "id": "xy-edge__webhook_1source-text-0-anonymize_text_1target-text-1",
                            "source": "webhook_1",
                            "target": "anonymize_text_1",
                            "sourceHandle": "source-text-0",
                            "targetHandle": "target-text-1"
                        }
                    ]
                },
                "input": [
                    {
                        "lane": "classifications",
                        "from": "classify_1"
                    },
                    {
                        "lane": "text",
                        "from": "webhook_1"
                    }
                ]
            },
            {
                "id": "response_1",
                "provider": "response",
                "config": {
                    "lanes": []
                },
                "ui": {
                    "position": {
                        "x": 640,
                        "y": 120
                    },
                    "measured": {
                        "width": 140,
                        "height": 264
                    },
                    "data": {
                        "class": "infrastructure",
                        "type": "default"
                    },
                    "formDataValid": true,
                    "edges": [
                        {
                            "selectable": true,
                            "deletable": true,
                            "id": "xy-edge__anonymize_text_1source-text-1-response_1target-text-6",
                            "source": "anonymize_text_1",
                            "target": "response_1",
                            "sourceHandle": "source-text-1",
                            "targetHandle": "target-text-6"
                        }
                    ]
                },
                "input": [
                    {
                        "lane": "text",
                        "from": "anonymize_text_1"
                    }
                ]
            }
        ],
        "source": "webhook_1",
        "project_id": "eb23d792-1d8d-4a95-9582-03feac99aa41"
    }
}

/**
 * Predefined pipeline configurations for common use cases
 * These are ready-to-use configurations that users can select from
 */
const PREDEFINED_PIPELINE_CONFIGS = {
  CENSOR_INTERNATIONAL_PII: {
    // Use the existing default configuration for International PII
    ...DEFAULT_PIPELINE_CONFIG
  },
  
  CENSOR_USA_PII: {
    pipeline: {
        "components": [
          {
            "id": "parse_1",
            "provider": "parse",
            "config": {},
            "ui": {
              "position": {
                "x": 180,
                "y": 60
              },
              "measured": {
                "width": 140,
                "height": 123
              },
              "data": {
                "class": "data",
                "type": "default"
              },
              "formDataValid": true,
              "edges": [
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__webhook_1source-tags-0-parse_1target-tags-0",
                  "source": "webhook_1",
                  "target": "parse_1",
                  "sourceHandle": "source-tags-0",
                  "targetHandle": "target-tags-0"
                }
              ]
            },
            "input": [
              {
                "lane": "tags",
                "from": "webhook_1"
              }
            ]
          },
          {
            "id": "classify_1",
            "provider": "classify",
            "config": {
              "classifications": [
                {
                  "name": "United States Personal Data Policy",
                  "description": "Detects personal data applicable to United States's Federal and State laws, including The Federal Trade Commission Act (FTC Act), the Financial Services Modernization Act (Gramm-Leach-Bliley Act (GLB/GLBA)), the Health Insurance Portability and Accountability Act (HIPAA), the Fair Credit Reporting Act (FCRA), the Fair and Accurate Credit Transactions Act (FACTA), among many others.",
                  "policyRule": {
                    "DlpPolicyTemplate": {
                      "Attributes": {
                        "xmlns": "http://schemas.nucleuz.com/2013/dlp_policy"
                      },
                      "Metadata": [
                        {
                          "Attributes": {
                            "id": "6804f220-9e66-6a42-a4e6-d53b11f2b91b",
                            "formatVersion": "101"
                          },
                          "Name": [
                            {
                              "Value": "United States Personal Data Policy",
                              "Attributes": {
                                "langcode": "en",
                                "default": "true"
                              }
                            }
                          ],
                          "Description": [
                            {
                              "Value": "Detects personal data applicable to United States's Federal and State laws, including The Federal Trade Commission Act (FTC Act), the Financial Services Modernization Act (Gramm-Leach-Bliley Act (GLB/GLBA)), the Health Insurance Portability and Accountability Act (HIPAA), the Fair Credit Reporting Act (FCRA), the Fair and Accurate Credit Transactions Act (FACTA), among many others.",
                              "Attributes": {
                                "langcode": "en",
                                "default": "true"
                              }
                            }
                          ],
                          "Version": [
                            {
                              "Attributes": {
                                "major": "2024",
                                "minor": "9",
                                "build": "0",
                                "revision": "12982"
                              }
                            }
                          ],
                          "Categories": [
                            {
                              "Locations": [
                                {
                                  "Location": [
                                    {
                                      "Attributes": {
                                        "idRef": "L6.21"
                                      }
                                    }
                                  ]
                                }
                              ],
                              "Industries": [
                                {
                                  "Industry": [
                                    {
                                      "Attributes": {
                                        "idRef": "I_ALL"
                                      }
                                    }
                                  ]
                                }
                              ],
                              "Regulations_Laws": [
                                {
                                  "Regulation_Law": [
                                    {
                                      "Attributes": {
                                        "idRef": "R53"
                                      }
                                    },
                                    {
                                      "Attributes": {
                                        "idRef": "R1"
                                      }
                                    },
                                    {
                                      "Attributes": {
                                        "idRef": "R2"
                                      }
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                      ],
                      "Rules": [
                        {
                          "Rule": [
                            {
                              "Attributes": {
                                "id": "Default_"
                              },
                              "FormatVersion": [
                                {
                                  "Attributes": {
                                    "version": "1"
                                  },
                                  "Condition": [
                                    {
                                      "Or": [
                                        {
                                          "Attributes": {
                                            "min": "1",
                                            "earlyOut": "true"
                                          },
                                          "And": [
                                            {
                                              "Or": [
                                                {
                                                  "Attributes": {
                                                    "min": "2"
                                                  },
                                                  "ClassificationRule": [
                                                    {
                                                      "Attributes": {
                                                        "idRef": "4781f188-f04e-a954-8480-fc670bdc4e61"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "0cbcdb45-1c61-81a1-233b-5a05c9a16080",
                                                        "minCount": "10"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "7c65fe2e-79e7-3f19-cf33-b18228744cb9"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "de8414dd-2b62-006a-8d37-ab76ed468d46",
                                                        "minCount": "4"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "b5d1e90c-2916-1354-845d-8a67cecc2723",
                                                        "minConfidence": "85"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "7c0f72ed-2cc7-5b50-50ad-7d7d576a561c"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "fd3de727-8676-8d93-5582-d6ae4502ccc5",
                                                        "minCount": "4"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "fdb635cc-97a9-89eb-844f-f2eb632aa458"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "0b76b606-465d-5615-9f29-7a0043cf1cc8"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "1496074a-cc29-8d17-9944-172bdea942b9"
                                                      }
                                                    }
                                                  ]
                                                }
                                              ],
                                              "Not": [
                                                {
                                                  "Or": [
                                                    {
                                                      "ClassificationRule": [
                                                        {
                                                          "Attributes": {
                                                            "idRef": "99b3cf23-2540-718f-6b3f-8acacb103f0d"
                                                          }
                                                        },
                                                        {
                                                          "Attributes": {
                                                            "idRef": "e087fe53-a96b-5e2a-6bba-f4160563d2d0"
                                                          }
                                                        }
                                                      ]
                                                    }
                                                  ]
                                                }
                                              ]
                                            },
                                            {
                                              "Or": [
                                                {
                                                  "ClassificationRule": [
                                                    {
                                                      "Attributes": {
                                                        "idRef": "407b6e49-8d5c-16ee-841b-6771bfcbc9b3",
                                                        "minConfidence": "70"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "162eae37-1a3e-2edb-51d2-7a96e9d4d732"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "8ac32a03-6b8a-01ae-82e4-012a133c6042",
                                                        "patternMode": "withinConfidenceRange",
                                                        "minConfidence": "85"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "222066f3-abfc-3065-5b8f-4037c1ba4398"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "dc7a8728-ed43-712a-ec1a-60a108cae6ca"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "28454a83-a3bd-513c-cb13-6adea3b4fd28"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "1a78c925-2007-88ec-5cd2-41a8127c038d"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "247b8d70-6e25-7bfe-ca36-6ee82d64a7e0",
                                                        "minConfidence": "75",
                                                        "patternMode": "withinConfidenceRange"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "5ef8c49a-7a7c-4b82-9a07-cd655e29e0f0"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "55a4b62c-7cbd-1f5e-d7b2-69e3535bb4b5"
                                                      }
                                                    },
                                                    {
                                                      "Attributes": {
                                                        "idRef": "c2118716-9f9e-43e6-ad66-e6c2e64c4ce0"
                                                      }
                                                    }
                                                  ]
                                                }
                                              ],
                                              "Not": [
                                                {
                                                  "Or": [
                                                    {
                                                      "ClassificationRule": [
                                                        {
                                                          "Attributes": {
                                                            "idRef": "43a6b97b-50ab-436a-c8b9-7dee6eac2ee7"
                                                          }
                                                        },
                                                        {
                                                          "Attributes": {
                                                            "idRef": "ed0d51ee-174b-ae54-c014-8df8ba24dd97"
                                                          }
                                                        }
                                                      ]
                                                    }
                                                  ]
                                                }
                                              ]
                                            }
                                          ]
                                        }
                                      ]
                                    }
                                  ],
                                  "Actions": [
                                    {
                                      "US_PII_Content_Detected": [
                                        ""
                                      ]
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  },
                  "policyGuid": "6804f220-9e66-6a42-a4e6-d53b11f2b91b",
                  "rules": [
                    "4781f188-f04e-a954-8480-fc670bdc4e61",
                    "0cbcdb45-1c61-81a1-233b-5a05c9a16080",
                    "7c65fe2e-79e7-3f19-cf33-b18228744cb9",
                    "de8414dd-2b62-006a-8d37-ab76ed468d46",
                    "b5d1e90c-2916-1354-845d-8a67cecc2723",
                    "7c0f72ed-2cc7-5b50-50ad-7d7d576a561c",
                    "fd3de727-8676-8d93-5582-d6ae4502ccc5",
                    "407b6e49-8d5c-16ee-841b-6771bfcbc9b3",
                    "162eae37-1a3e-2edb-51d2-7a96e9d4d732",
                    "8ac32a03-6b8a-01ae-82e4-012a133c6042",
                    "222066f3-abfc-3065-5b8f-4037c1ba4398",
                    "dc7a8728-ed43-712a-ec1a-60a108cae6ca",
                    "28454a83-a3bd-513c-cb13-6adea3b4fd28",
                    "1a78c925-2007-88ec-5cd2-41a8127c038d",
                    "247b8d70-6e25-7bfe-ca36-6ee82d64a7e0"
                  ]
                }
              ]
            },
            "ui": {
              "position": {
                "x": 400,
                "y": 140
              },
              "measured": {
                "width": 140,
                "height": 77
              },
              "data": {
                "class": "text",
                "type": "default"
              },
              "formDataValid": true,
              "edges": [
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__parse_1source-text-0-classify_1target-text-0",
                  "source": "parse_1",
                  "target": "classify_1",
                  "sourceHandle": "source-text-0",
                  "targetHandle": "target-text-0"
                },
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__webhook_1source-text-0-classify_1target-text-0",
                  "source": "webhook_1",
                  "target": "classify_1",
                  "sourceHandle": "source-text-0",
                  "targetHandle": "target-text-0"
                }
              ]
            },
            "input": [
              {
                "lane": "text",
                "from": "parse_1"
              },
              {
                "lane": "text",
                "from": "webhook_1"
              }
            ]
          },
          {
            "id": "anonymize_text_1",
            "provider": "anonymize_text",
            "config": {
              "profile": "glinerMergedLarge",
              "glinerMergedLarge": {
                "anonymizeChar": "█"
              },
              "glinerCommunitySmall": {
                "anonymizeChar": "█"
              }
            },
            "ui": {
              "position": {
                "x": 400,
                "y": 240
              },
              "measured": {
                "width": 140,
                "height": 90
              },
              "data": {
                "class": "text",
                "type": "default"
              },
              "formDataValid": true,
              "edges": [
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__classify_1source-classifications-0-anonymize_text_1target-classifications-0",
                  "source": "classify_1",
                  "target": "anonymize_text_1",
                  "sourceHandle": "source-classifications-0",
                  "targetHandle": "target-classifications-0"
                },
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__parse_1source-text-0-anonymize_text_1target-text-1",
                  "source": "parse_1",
                  "target": "anonymize_text_1",
                  "sourceHandle": "source-text-0",
                  "targetHandle": "target-text-1"
                },
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__webhook_1source-text-0-anonymize_text_1target-text-1",
                  "source": "webhook_1",
                  "target": "anonymize_text_1",
                  "sourceHandle": "source-text-0",
                  "targetHandle": "target-text-1"
                }
              ]
            },
            "input": [
              {
                "lane": "classifications",
                "from": "classify_1"
              },
              {
                "lane": "text",
                "from": "parse_1"
              },
              {
                "lane": "text",
                "from": "webhook_1"
              }
            ]
          },
          {
            "id": "response_1",
            "provider": "response",
            "config": {
              "lanes": []
            },
            "ui": {
              "position": {
                "x": 580,
                "y": 120
              },
              "measured": {
                "width": 140,
                "height": 264
              },
              "data": {
                "class": "infrastructure",
                "type": "default"
              },
              "formDataValid": true,
              "edges": [
                {
                  "selectable": true,
                  "deletable": true,
                  "id": "xy-edge__anonymize_text_1source-text-1-response_1target-text-6",
                  "source": "anonymize_text_1",
                  "target": "response_1",
                  "sourceHandle": "source-text-1",
                  "targetHandle": "target-text-6"
                }
              ]
            },
            "input": [
              {
                "lane": "text",
                "from": "anonymize_text_1"
              }
            ]
          },
          {
            "id": "webhook_1",
            "provider": "webhook",
            "config": {
              "hideForm": true,
              "mode": "Source",
              "type": "webhook"
            },
            "ui": {
              "position": {
                "x": 0,
                "y": 220
              },
              "measured": {
                "width": 140,
                "height": 123
              },
              "data": {
                "class": "source",
                "type": "default"
              },
              "formDataValid": true
            }
          }
        ],
        "id": "c71ab76c-d609-42ed-ad32-7c966e8c778b"
    }
  },
  
  CENSOR_HIPAA_DATA: {
    // Use the existing HIPAA configuration as the default
    ...DEFAULT_PIPELINE_CONFIG
  }
};

/**
 * Extract all strings from any data structure recursively
 * @param {any} data - The data to extract strings from
 * @param {string} path - Current path in the data structure
 * @returns {Array} - Array of {value, path} objects
 */
function extractStrings(data, path = '') {
  const strings = [];
  
  if (typeof data === 'string') {
    strings.push({ value: data, path: path });
  } else if (Array.isArray(data)) {
    data.forEach((item, index) => {
      const newPath = path ? `${path}.${index}` : `${index}`;
      strings.push(...extractStrings(item, newPath));
    });
  } else if (data && typeof data === 'object') {
    Object.keys(data).forEach(key => {
      const newPath = path ? `${path}.${key}` : key;
      strings.push(...extractStrings(data[key], newPath));
    });
  }
  
  return strings;
}

/**
 * Replace strings in data structure using the censored results
 * @param {any} data - The original data structure
 * @param {Map} stringMap - Map of original strings to censored strings
 * @param {string} path - Current path in the data structure
 * @param {boolean} isRootString - Whether this is a root-level string (not in object/array)
 * @returns {any} - Data structure with censored strings
 */
function replaceStrings(data, stringMap, path = '', isRootString = false) {
  if (typeof data === 'string') {
    const censoredString = stringMap.get(data) || data;
    
    // For root-level strings (single string input), keep the \n\n characters
    // For strings in objects/arrays, remove the \n\n characters
    if (isRootString) {
      return censoredString;
    } else {
      // Remove trailing \n\n characters for strings in objects/arrays
      return censoredString.replace(/\n+$/, '');
    }
  } else if (Array.isArray(data)) {
    return data.map((item, index) => {
      const newPath = path ? `${path}.${index}` : `${index}`;
      return replaceStrings(item, stringMap, newPath, false);
    });
  } else if (data && typeof data === 'object') {
    const result = {};
    Object.keys(data).forEach(key => {
      const newPath = path ? `${path}.${key}` : key;
      result[key] = replaceStrings(data[key], stringMap, newPath, false);
    });
    return result;
  }
  
  return data;
}

/**
 * Aparavi DTC Universal Client for PII Anonymization
 * Compatible with both Node.js and browser environments
 * @class
 */
class AparaviDTC {
  /**
   * Create a new AparaviDTC instance
   * @param {string} apiKey - Your Aparavi DTC API key
   */
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.apiBaseUrl = 'https://eaas.aparavi.com';
    this.token = null;
    this.type = null;
    
    // Set up cleanup handlers for both environments
    this.setupCleanupHandlers();
  }

  /**
   * Setup cleanup handlers for different environments
   * @private
   */
  setupCleanupHandlers() {
    // Node.js cleanup
    if (typeof process !== 'undefined') {
      process.on('SIGINT', () => this.cleanup());
      process.on('SIGTERM', () => this.cleanup());
      process.on('exit', () => this.cleanup());
    }
    
    // Browser cleanup
    if (typeof window !== 'undefined') {
      window.addEventListener('beforeunload', () => this.cleanup());
      window.addEventListener('unload', () => this.cleanup());
    }
  }

  /**
   * Clean up resources and teardown pipeline
   * @private
   */
  async cleanup() {
    if (this.token && this.type) {
      try {
        await this.tearDown();
      } catch (error) {
        console.warn('Cleanup warning:', error.message);
      }
    }
  }

  /**
   * Get the pipeline configuration
   * @returns {Object} - Pipeline configuration object
   * @private
   */
  getPipelineJson() {
    // Return the stored pipeline configuration
    // Handle both nested structure (pipeline.pipeline) and flat structure (direct export from DTC)
    if (this.pipelineConfig.pipeline) {
      return this.pipelineConfig.pipeline;
    }
    return this.pipelineConfig;
  }


  /**
   * Validate the pipeline configuration
   * @param {Object} pipelineJson - Pipeline configuration to validate
   * @returns {Promise<Object>} - Validation result
   * @private
   */
  async validatePipeline(pipelineJson) {
    try {
      const response = await fetch(`${this.apiBaseUrl}/pipe/validate`, {
        method: 'POST',
        headers: {
          'Authorization': this.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(pipelineJson)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Pipeline validation failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      throw new Error(`Pipeline validation error: ${error.message}`);
    }
  }

  /**
   * Execute the pipeline
   * @param {Object} pipelineJson - Pipeline configuration to execute
   * @returns {Promise<Object>} - Execution result
   * @private
   */
  async executePipeline(pipelineJson) {
    try {
      // The API expects the pipeline configuration to be wrapped in a 'pipeline' key
      const requestBody = {
        pipeline: pipelineJson
      };
      
      const response = await fetch(`${this.apiBaseUrl}/task`, {
        method: 'PUT',
        headers: {
          'Authorization': this.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Pipeline execution failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      throw new Error(`Pipeline execution error: ${error.message}`);
    }
  }

  /**
   * Get the current pipeline status
   * @returns {Promise<Object>} - Pipeline status information
   * @private
   */
  async getPipelineStatus() {
    if (!this.token || !this.type) {
      throw new Error('No active pipeline. Call startPIIPipeline first.');
    }

    try {
      const response = await fetch(`${this.apiBaseUrl}/task?token=${this.token}&type=${this.type}`, {
        method: 'GET',
        headers: {
          'Authorization': this.apiKey
        }
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Status check failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      throw new Error(`Status check error: ${error.message}`);
    }
  }

  /**
   * Wait for the pipeline to reach running status
   * @param {number} [timeoutMinutes=10] - Timeout in minutes
   * @returns {Promise<void>}
   * @private
   */
  async waitForRunningStatus(timeoutMinutes = 10) {
    if (!this.token || !this.type) {
      throw new Error('No active pipeline. Call startPIIPipeline first.');
    }

    console.log('⏳ Waiting for pipeline to reach Running status...');
    let taskStatus = await this.getPipelineStatus();
    const startTime = Date.now();
    const timeout = timeoutMinutes * 60 * 1000;

    while (taskStatus.data.status !== 'Running' && !taskStatus.data.completed) {
      if (Date.now() - startTime > timeout) {
        throw new Error(`Pipeline failed to reach Running status within ${timeoutMinutes} minutes`);
      }
      
      console.log(`📊 Current status: ${taskStatus.data.status} (${Math.round((Date.now() - startTime) / 1000)}s elapsed)`);
      
      // Wait 2 seconds before next check
      await new Promise(resolve => setTimeout(resolve, 2000));
      taskStatus = await this.getPipelineStatus();
    }

    console.log(`🎉 Pipeline is now Running! Status: ${taskStatus.data.status}`);
    return taskStatus;
  }

  /**
   * Start the PII anonymization pipeline
   * @returns {Promise<void>}
   */
  async startPIIPipeline() {
    try {
      const pipelineJson = this.getPipelineJson();
      
      if (!pipelineJson) {
        throw new Error('Pipeline configuration not found');
      }

      console.log('🔍 Pipeline JSON loaded successfully');
      console.log('🔍 Pipeline source component:', pipelineJson.components.find(c => c.provider === 'webhook' || c.type === 'webhook')?.id);
      console.log('🔍 Pipeline components:', pipelineJson.components.map(c => c.id).join(','));

      // Validate the pipeline
      console.log('🔍 Validating pipeline...');
      const validationResult = await this.validatePipeline(pipelineJson);
      console.log('✅ Pipeline validation successful:', validationResult);

      // Execute the pipeline
      console.log('🚀 Starting PII anonymization pipeline...');
      const response = await this.executePipeline(pipelineJson);
      
      if (response && response.data) {
        this.token = response.data.token;
        this.type = response.data.type;
        console.log(`🎯 Pipeline started - Token: ${this.token}, Type: ${this.type}`);
      }

      if (response?.errors?.length) {
        throw new Error(response.errors[0]);
      }

      // Wait for the pipeline to reach Running status
      await this.waitForRunningStatus();

      console.log('✅ Pipeline started successfully!');
      return response;
    } catch (error) {
      console.error('❌ Error starting PII pipeline:', error.message);
      throw error;
    }
  }

  /**
   * Send text for PII anonymization
   * @param {string} textData - Text containing PII to anonymize
   * @returns {Promise<string>} - Anonymized text
   */
  async sendText(textData) {
    if (!this.token || !this.type) {
      throw new Error('No active pipeline. Call startPIIPipeline first.');
    }

    console.log(`📤 Sending text to pipeline webhook...`);
    console.log(`🔗 Webhook URL: ${this.apiBaseUrl}/webhook?type=${this.type}&apikey=${this.apiKey}&token=${this.token}`);

    try {
      const response = await fetch(`${this.apiBaseUrl}/webhook?type=${this.type}&apikey=${this.apiKey}&token=${this.token}`, {
        method: 'PUT',
        headers: {
          'Authorization': this.apiKey,
          'Content-Type': 'text/plain'
        },
        body: textData
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Webhook request failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const result = await response.json();
      
      console.log('📥 Webhook response received:', JSON.stringify(result, null, 2));
      console.log('✅ Text anonymized successfully');
      
      // Extract the cleaned text from the response
      // The response should contain the anonymized text in the objects section
      if (result.data && result.data.objects) {
        const objectKeys = Object.keys(result.data.objects);
        if (objectKeys.length > 0) {
          const firstObject = result.data.objects[objectKeys[0]];
          if (firstObject.text && firstObject.text.length > 0) {
            const cleanedText = firstObject.text[0];
            
            // Return only the cleaned text string
            return cleanedText;
          }
        }
      }
      
      // If we can't extract the cleaned text, return the full response for debugging
      console.warn('⚠️ Could not extract cleaned text from response, returning full response');
      return result;
      
    } catch (error) {
      throw new Error(`Webhook request error: ${error.message}`);
    }
  }

  /**
   * Clean up the pipeline and resources
   * @returns {Promise<void>}
   */
  async tearDown() {
    if (!this.token || !this.type) {
      console.log('ℹ️ No active pipeline to tear down');
      return;
    }

    console.log(`🧹 Cleaning up pipeline: ${this.token} (${this.type})`);

    try {
      const response = await fetch(`${this.apiBaseUrl}/task?type=${this.type}&token=${this.token}`, {
        method: 'DELETE',
        headers: {
          'Authorization': this.apiKey
        }
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Pipeline teardown failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      console.log('✅ Pipeline teardown successful');
      this.token = null;
      this.type = null;
    } catch (error) {
      console.error('❌ Pipeline teardown error:', error.message);
      throw error;
    }
  }

  /**
   * Censor International PII using predefined configuration
   * @param {string|Array|Object} input - Text, array of strings, or object/array of objects containing PII to anonymize
   * @returns {Promise<string|Array|Object>} - Anonymized data with same structure as input
   */
  async censorInternationalPII(input) {
    // Use hardcoded International PII configuration
    this.pipelineConfig = PREDEFINED_PIPELINE_CONFIGS.CENSOR_INTERNATIONAL_PII;
    
    // Handle different input types
    if (typeof input === 'string') {
      // Single string - current behavior
      await this.startPIIPipeline();
      const result = await this.sendText(input);
      await this.tearDown();
      return result;
      
    } else if (Array.isArray(input)) {
      // Check if array of strings or array of objects
      if (input.every(item => typeof item === 'string')) {
        // Array of strings - batch process
        await this.startPIIPipeline();
        const results = [];
        for (const string of input) {
          const censored = await this.sendText(string);
          // Remove trailing \n\n characters for array of strings
          results.push(censored.replace(/\n+$/, ''));
        }
        await this.tearDown();
        return results;
        
      } else {
        // Array of objects - extract all strings, batch process, reconstruct
        const stringData = extractStrings(input);
        if (stringData.length === 0) {
          return input; // No strings to process
        }
        
        await this.startPIIPipeline();
        const stringMap = new Map();
        
        // Process all strings sequentially
        for (const { value, path } of stringData) {
          const censored = await this.sendText(value);
          stringMap.set(value, censored);
        }
        
        await this.tearDown();
        
        // Reconstruct the original structure with censored strings
        return replaceStrings(input, stringMap, '', false);
      }
      
    } else if (typeof input === 'object' && input !== null) {
      // Single object - extract strings, batch process, reconstruct
      const stringData = extractStrings(input);
      if (stringData.length === 0) {
        return input; // No strings to process
      }
      
      await this.startPIIPipeline();
      const stringMap = new Map();
      
      // Process all strings sequentially
      for (const { value, path } of stringData) {
        const censored = await this.sendText(value);
        stringMap.set(value, censored);
      }
      
      await this.tearDown();
      
      // Reconstruct the original structure with censored strings
      return replaceStrings(input, stringMap, '', false);
      
    } else {
      // Non-string, non-object, non-array - return as is
      return input;
    }
  }

  /**
   * Censor USA PII using predefined configuration
   * @param {string|Array|Object} input - Text, array of strings, or object/array of objects containing PII to anonymize
   * @returns {Promise<string|Array|Object>} - Anonymized data with same structure as input
   */
  async censorUSAPII(input) {
    // Use hardcoded USA PII configuration
    this.pipelineConfig = PREDEFINED_PIPELINE_CONFIGS.CENSOR_USA_PII;
    
    // Handle different input types
    if (typeof input === 'string') {
      // Single string - current behavior
      await this.startPIIPipeline();
      const result = await this.sendText(input);
      await this.tearDown();
      return result;
      
    } else if (Array.isArray(input)) {
      // Check if array of strings or array of objects
      if (input.every(item => typeof item === 'string')) {
        // Array of strings - batch process
        await this.startPIIPipeline();
        const results = [];
        for (const string of input) {
          const censored = await this.sendText(string);
          // Remove trailing \n\n characters for array of strings
          results.push(censored.replace(/\n+$/, ''));
        }
        await this.tearDown();
        return results;
        
      } else {
        // Array of objects - extract all strings, batch process, reconstruct
        const stringData = extractStrings(input);
        if (stringData.length === 0) {
          return input; // No strings to process
        }
        
        await this.startPIIPipeline();
        const stringMap = new Map();
        
        // Process all strings sequentially
        for (const { value, path } of stringData) {
          const censored = await this.sendText(value);
          stringMap.set(value, censored);
        }
        
        await this.tearDown();
        
        // Reconstruct the original structure with censored strings
        return replaceStrings(input, stringMap, '', false);
      }
      
    } else if (typeof input === 'object' && input !== null) {
      // Single object - extract strings, batch process, reconstruct
      const stringData = extractStrings(input);
      if (stringData.length === 0) {
        return input; // No strings to process
      }
      
      await this.startPIIPipeline();
      const stringMap = new Map();
      
      // Process all strings sequentially
      for (const { value, path } of stringData) {
        const censored = await this.sendText(value);
        stringMap.set(value, censored);
      }
      
      await this.tearDown();
      
      // Reconstruct the original structure with censored strings
      return replaceStrings(input, stringMap, '', false);
      
    } else {
      // Non-string, non-object, non-array - return as is
      return input;
    }
  }

  /**
   * Censor HIPAA data using predefined configuration
   * @param {string|Array|Object} input - Text, array of strings, or object/array of objects containing PII to anonymize
   * @returns {Promise<string|Array|Object>} - Anonymized data with same structure as input
   */
  async censorHIPAAData(input) {
    // Use hardcoded HIPAA configuration
    this.pipelineConfig = PREDEFINED_PIPELINE_CONFIGS.CENSOR_HIPAA_DATA;
    
    // Handle different input types
    if (typeof input === 'string') {
      // Single string - current behavior
      await this.startPIIPipeline();
      const result = await this.sendText(input);
      await this.tearDown();
      return result;
      
    } else if (Array.isArray(input)) {
      // Check if array of strings or array of objects
      if (input.every(item => typeof item === 'string')) {
        // Array of strings - batch process
        await this.startPIIPipeline();
        const results = [];
        for (const string of input) {
          const censored = await this.sendText(string);
          // Remove trailing \n\n characters for array of strings
          results.push(censored.replace(/\n+$/, ''));
        }
        await this.tearDown();
        return results;
        
      } else {
        // Array of objects - extract all strings, batch process, reconstruct
        const stringData = extractStrings(input);
        if (stringData.length === 0) {
          return input; // No strings to process
        }
        
        await this.startPIIPipeline();
        const stringMap = new Map();
        
        // Process all strings sequentially
        for (const { value, path } of stringData) {
          const censored = await this.sendText(value);
          stringMap.set(value, censored);
        }
        
        await this.tearDown();
        
        // Reconstruct the original structure with censored strings
        return replaceStrings(input, stringMap, '', false);
      }
      
    } else if (typeof input === 'object' && input !== null) {
      // Single object - extract strings, batch process, reconstruct
      const stringData = extractStrings(input);
      if (stringData.length === 0) {
        return input; // No strings to process
      }
      
      await this.startPIIPipeline();
      const stringMap = new Map();
      
      // Process all strings sequentially
      for (const { value, path } of stringData) {
        const censored = await this.sendText(value);
        stringMap.set(value, censored);
      }
      
      await this.tearDown();
      
      // Reconstruct the original structure with censored strings
      return replaceStrings(input, stringMap, '', false);
      
    } else {
      // Non-string, non-object, non-array - return as is
      return input;
    }
  }

}

// Universal export/import handling
if (typeof module !== 'undefined' && module.exports) {
  // Node.js CommonJS
  module.exports = AparaviDTC;
} else if (typeof define === 'function' && define.amd) {
  // AMD (RequireJS)
  define([], function() { return AparaviDTC; });
} else if (typeof window !== 'undefined') {
  // Browser global
  window.AparaviDTC = AparaviDTC;
} else if (typeof global !== 'undefined') {
  // Node.js global
  global.AparaviDTC = AparaviDTC;
}

// ES Module export (for modern environments)
if (typeof exports !== 'undefined') {
  exports.AparaviDTC = AparaviDTC;
}